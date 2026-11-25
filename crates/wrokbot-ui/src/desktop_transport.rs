//! WASM 侧 Tauri structured Channel adapter；Web 宿主不进入本模块的 IPC 路径。

#[cfg(any(test, target_arch = "wasm32"))]
use std::collections::BTreeMap;

#[cfg(any(test, target_arch = "wasm32"))]
use openbot_contracts::desktop::DesktopStructuredEventFrame;

#[cfg(any(test, target_arch = "wasm32"))]
const MAX_REORDERED_CHANNEL_FRAMES: usize = 257;
#[cfg(any(test, target_arch = "wasm32"))]
const TAURI_RUNTIME_FLAG: &str = "isTauri";
#[cfg(any(test, target_arch = "wasm32"))]
const TAURI_INTERNALS_PROPERTY: &str = "__TAURI_INTERNALS__";
#[cfg(any(test, target_arch = "wasm32"))]
const TAURI_INVOKE_PROPERTY: &str = "invoke";
#[cfg(any(test, target_arch = "wasm32"))]
const TAURI_TRANSFORM_CALLBACK_PROPERTY: &str = "transformCallback";
#[cfg(any(test, target_arch = "wasm32"))]
const TAURI_UNREGISTER_CALLBACK_PROPERTY: &str = "unregisterCallback";

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, PartialEq, Eq)]
enum ChannelOrderError {
    DuplicateOrPast,
    MessageAtOrAfterEnd,
    MultipleEnds,
    TooManyPending,
    IndexExhausted,
}

#[cfg(any(test, target_arch = "wasm32"))]
struct OrderedChannel<T> {
    next_index: u64,
    pending: BTreeMap<u64, T>,
    end_index: Option<u64>,
    ended: bool,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug)]
struct OrderedBatch<T> {
    messages: Vec<T>,
    ended: bool,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl<T> OrderedChannel<T> {
    fn new() -> Self {
        Self {
            next_index: 0,
            pending: BTreeMap::new(),
            end_index: None,
            ended: false,
        }
    }

    fn push_message(
        &mut self,
        index: u64,
        message: T,
    ) -> Result<OrderedBatch<T>, ChannelOrderError> {
        if self.ended || index < self.next_index || self.pending.contains_key(&index) {
            return Err(ChannelOrderError::DuplicateOrPast);
        }
        if self.end_index.is_some_and(|end| index >= end) {
            return Err(ChannelOrderError::MessageAtOrAfterEnd);
        }
        self.pending.insert(index, message);
        if self.pending.len() > MAX_REORDERED_CHANNEL_FRAMES {
            return Err(ChannelOrderError::TooManyPending);
        }
        self.drain()
    }

    fn push_end(&mut self, index: u64) -> Result<OrderedBatch<T>, ChannelOrderError> {
        if self.ended || self.end_index.is_some() {
            return Err(ChannelOrderError::MultipleEnds);
        }
        if index < self.next_index || self.pending.keys().any(|pending| *pending >= index) {
            return Err(ChannelOrderError::MessageAtOrAfterEnd);
        }
        self.end_index = Some(index);
        self.drain()
    }

    fn drain(&mut self) -> Result<OrderedBatch<T>, ChannelOrderError> {
        let mut messages = Vec::new();
        while let Some(message) = self.pending.remove(&self.next_index) {
            messages.push(message);
            self.next_index = self
                .next_index
                .checked_add(1)
                .ok_or(ChannelOrderError::IndexExhausted)?;
        }
        let ended = self.end_index == Some(self.next_index);
        if ended {
            self.ended = true;
        }
        Ok(OrderedBatch { messages, ended })
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, PartialEq, Eq)]
enum WireSequenceError {
    SilentLoss,
    InconsistentGap,
    NotMonotonic,
    AfterTerminal,
    SequenceExhausted,
}

#[cfg(any(test, target_arch = "wasm32"))]
struct WireSequenceTracker {
    expected: u64,
    terminal_seen: bool,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl WireSequenceTracker {
    fn new() -> Self {
        Self {
            expected: 0,
            terminal_seen: false,
        }
    }

    fn observe(&mut self, frame: &DesktopStructuredEventFrame) -> Result<(), WireSequenceError> {
        if self.terminal_seen {
            return Err(WireSequenceError::AfterTerminal);
        }
        let sequence = frame.sequence();
        if let Some(gap) = frame.skipped() {
            if gap.from_sequence != self.expected
                || gap.through_sequence.checked_add(1) != Some(sequence)
            {
                return Err(WireSequenceError::InconsistentGap);
            }
            self.expected = sequence;
        }
        if sequence > self.expected {
            return Err(WireSequenceError::SilentLoss);
        }
        if sequence < self.expected {
            return Err(WireSequenceError::NotMonotonic);
        }
        self.expected = sequence
            .checked_add(1)
            .ok_or(WireSequenceError::SequenceExhausted)?;
        self.terminal_seen = frame.terminal_reason().is_some();
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use js_sys::{Function, JSON, Promise, Reflect};
    use openbot_contracts::command::{AppEvent, SubscriptionRequest};
    use openbot_contracts::desktop::{
        DESKTOP_STRUCTURED_CLOSE_COMMAND, DESKTOP_STRUCTURED_OPEN_COMMAND,
        DESKTOP_STRUCTURED_SUBSCRIPTION_ID_EXCLUSIVE_LIMIT, DesktopStructuredEventFrame,
        DesktopStructuredStreamKind, DesktopStructuredSubscriptionCloseRequest,
        DesktopStructuredSubscriptionOpened, DesktopStructuredTerminalReason,
    };
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast as _, JsValue};

    use super::{
        OrderedChannel, TAURI_INTERNALS_PROPERTY, TAURI_INVOKE_PROPERTY, TAURI_RUNTIME_FLAG,
        TAURI_TRANSFORM_CALLBACK_PROPERTY, TAURI_UNREGISTER_CALLBACK_PROPERTY, WireSequenceTracker,
    };

    const CHANNEL_PREFIX: &str = "__CHANNEL__:";
    const MAX_STRUCTURED_FRAME_JSON_BYTES: usize = 1024 * 1024;
    const MAX_PRE_RECEIPT_FRAMES: usize = 257;

    #[derive(Clone)]
    pub(crate) struct DesktopStructuredHandlers {
        on_event: Rc<dyn Fn(AppEvent) -> bool>,
        on_terminal: Rc<dyn Fn(DesktopStructuredTerminalReason)>,
        on_error: Rc<dyn Fn()>,
    }

    impl DesktopStructuredHandlers {
        pub(crate) fn new(
            on_event: impl Fn(AppEvent) -> bool + 'static,
            on_terminal: impl Fn(DesktopStructuredTerminalReason) + 'static,
            on_error: impl Fn() + 'static,
        ) -> Self {
            Self {
                on_event: Rc::new(on_event),
                on_terminal: Rc::new(on_terminal),
                on_error: Rc::new(on_error),
            }
        }
    }

    #[derive(Clone)]
    struct TauriInternals {
        object: JsValue,
        invoke: Function,
        transform_callback: Function,
        unregister_callback: Function,
    }

    enum DeliveryAction {
        Event(AppEvent),
        Terminal(DesktopStructuredTerminalReason),
    }

    struct ConnectionState {
        internals: TauriInternals,
        callback_id: u32,
        callback_registered: bool,
        expected_stream: DesktopStructuredStreamKind,
        subscription_id: Option<u64>,
        channel_order: OrderedChannel<JsValue>,
        wire_sequence: WireSequenceTracker,
        before_receipt: VecDeque<DesktopStructuredEventFrame>,
        channel_ended: bool,
        terminal_seen: bool,
        cancelled: bool,
        failed: bool,
        complete: bool,
        finish_resolver: Option<Function>,
        handlers: DesktopStructuredHandlers,
    }

    type CallbackSlot = Rc<RefCell<Option<Closure<dyn FnMut(JsValue)>>>>;

    pub(crate) struct DesktopStructuredConnection {
        state: Rc<RefCell<ConnectionState>>,
        callback_slot: CallbackSlot,
        finished: Promise,
    }

    impl DesktopStructuredConnection {
        pub(crate) async fn finished(&self) {
            _ = wasm_bindgen_futures::JsFuture::from(self.finished.clone()).await;
        }

        pub(crate) fn finished_promise(&self) -> Promise {
            self.finished.clone()
        }
    }

    impl Drop for DesktopStructuredConnection {
        fn drop(&mut self) {
            let subscription_id = {
                let mut state = self.state.borrow_mut();
                if state.complete || state.failed || state.cancelled {
                    None
                } else {
                    state.cancelled = true;
                    state.subscription_id
                }
            };
            unregister_callback(&self.state);
            if let Some(subscription_id) = subscription_id {
                invoke_close(&self.state, subscription_id);
            }
            resolve_finished(&self.state);
            // If open is still pending, its transferred one-shot callbacks retain this slot until
            // the receipt/error arrives and perform the same cleanup without leaking the closure.
            if self.state.borrow().subscription_id.is_some() {
                self.callback_slot.borrow_mut().take();
            }
        }
    }

    pub(crate) fn is_tauri_host() -> bool {
        web_sys::window().is_some_and(|window| {
            Reflect::get(window.as_ref(), &JsValue::from_str(TAURI_RUNTIME_FLAG))
                .ok()
                .and_then(|value| value.as_bool())
                == Some(true)
        })
    }

    pub(crate) fn open_desktop_structured(
        request: SubscriptionRequest,
        handlers: DesktopStructuredHandlers,
    ) -> Result<DesktopStructuredConnection, ()> {
        let internals = tauri_internals()?;
        let expected_stream = DesktopStructuredStreamKind::from_request(&request);
        let finish_resolver = Rc::new(RefCell::new(None::<Function>));
        let resolver_slot = Rc::clone(&finish_resolver);
        let finished = Promise::new(&mut |resolve, _reject| {
            resolver_slot.replace(Some(resolve));
        });
        let finish_resolver = finish_resolver.borrow_mut().take().ok_or(())?;
        let state_slot = Rc::new(RefCell::new(None::<Rc<RefCell<ConnectionState>>>));
        let callback_state = Rc::clone(&state_slot);
        let callback = Closure::<dyn FnMut(JsValue)>::new(move |payload| {
            if let Some(state) = callback_state.borrow().as_ref() {
                receive_channel_payload(state, payload);
            }
        });
        let raw_callback_id = internals
            .transform_callback
            .call2(&internals.object, callback.as_ref(), &JsValue::FALSE)
            .map_err(|_| ())?;
        let callback_id = raw_callback_id
            .as_f64()
            .filter(|value| value.is_finite() && value.fract() == 0.0)
            .and_then(|value| u32::try_from(value as u64).ok())
            .ok_or_else(|| {
                _ = internals
                    .unregister_callback
                    .call1(&internals.object, &raw_callback_id);
            })?;
        let callback_slot = Rc::new(RefCell::new(Some(callback)));
        let state = Rc::new(RefCell::new(ConnectionState {
            internals: internals.clone(),
            callback_id,
            callback_registered: true,
            expected_stream,
            subscription_id: None,
            channel_order: OrderedChannel::new(),
            wire_sequence: WireSequenceTracker::new(),
            before_receipt: VecDeque::new(),
            channel_ended: false,
            terminal_seen: false,
            cancelled: false,
            failed: false,
            complete: false,
            finish_resolver: Some(finish_resolver),
            handlers,
        }));
        state_slot.replace(Some(Rc::clone(&state)));

        let args = match to_js(serde_json::json!({
            "request": request,
            "channel": format!("{CHANNEL_PREFIX}{callback_id}"),
        })) {
            Ok(args) => args,
            Err(()) => {
                unregister_callback(&state);
                callback_slot.borrow_mut().take();
                return Err(());
            }
        };
        let promise = match invoke(&internals, DESKTOP_STRUCTURED_OPEN_COMMAND, &args) {
            Ok(promise) => promise,
            Err(()) => {
                unregister_callback(&state);
                callback_slot.borrow_mut().take();
                return Err(());
            }
        };
        install_open_settlement(&promise, &state, &callback_slot);
        Ok(DesktopStructuredConnection {
            state,
            callback_slot,
            finished,
        })
    }

    fn install_open_settlement(
        promise: &Promise,
        state: &Rc<RefCell<ConnectionState>>,
        callback_slot: &CallbackSlot,
    ) {
        let fulfilled_state = Rc::clone(state);
        let fulfilled_slot = Rc::clone(callback_slot);
        let fulfilled = Closure::<dyn FnMut(JsValue)>::new(move |value: JsValue| {
            let receipt = from_js_string(&value).and_then(|json| {
                serde_json::from_str::<DesktopStructuredSubscriptionOpened>(&json).map_err(|_| ())
            });
            match receipt {
                Ok(receipt) => install_receipt(&fulfilled_state, receipt.subscription_id),
                Err(()) => fail(&fulfilled_state),
            }
            if fulfilled_state.borrow().cancelled || fulfilled_state.borrow().failed {
                unregister_callback(&fulfilled_state);
                fulfilled_slot.borrow_mut().take();
            }
        })
        .into_js_value();
        let rejected_state = Rc::clone(state);
        let rejected_slot = Rc::clone(callback_slot);
        let rejected = Closure::<dyn FnMut(JsValue)>::new(move |_error: JsValue| {
            if !rejected_state.borrow().cancelled {
                fail(&rejected_state);
            }
            unregister_callback(&rejected_state);
            rejected_slot.borrow_mut().take();
        })
        .into_js_value();
        if let Ok(then) = function(promise.as_ref(), "then") {
            if then.call2(promise.as_ref(), &fulfilled, &rejected).is_err() {
                fail(state);
            }
        } else {
            fail(state);
        }
    }

    fn install_receipt(state: &Rc<RefCell<ConnectionState>>, subscription_id: u64) {
        let (duplicate, cancelled_or_failed, frames, ended) = {
            let mut current = state.borrow_mut();
            let duplicate = current.subscription_id.replace(subscription_id).is_some();
            (
                duplicate,
                current.cancelled || current.failed,
                current.before_receipt.drain(..).collect::<Vec<_>>(),
                current.channel_ended,
            )
        };
        if duplicate {
            fail(state);
            return;
        }
        if cancelled_or_failed {
            invoke_close(state, subscription_id);
            return;
        }
        for frame in frames {
            if deliver_frame(state, frame).is_err() {
                fail(state);
                return;
            }
        }
        if ended {
            finish_channel_end(state);
        }
    }

    fn receive_channel_payload(state: &Rc<RefCell<ConnectionState>>, payload: JsValue) {
        if state.borrow().failed || state.borrow().complete || state.borrow().cancelled {
            return;
        }
        let packet = parse_channel_packet(&payload);
        let batch = match packet {
            Ok(ChannelPacket::Message { index, message }) => state
                .borrow_mut()
                .channel_order
                .push_message(index, message),
            Ok(ChannelPacket::End { index }) => state.borrow_mut().channel_order.push_end(index),
            Err(()) => {
                fail(state);
                return;
            }
        };
        let batch = match batch {
            Ok(batch) => batch,
            Err(_) => {
                fail(state);
                return;
            }
        };
        for message in batch.messages {
            let frame = match frame_from_channel_message(&message) {
                Ok(frame) => frame,
                Err(()) => {
                    fail(state);
                    return;
                }
            };
            if state.borrow().subscription_id.is_none() {
                let mut current = state.borrow_mut();
                if current.before_receipt.len() >= MAX_PRE_RECEIPT_FRAMES {
                    drop(current);
                    fail(state);
                    return;
                }
                current.before_receipt.push_back(frame);
            } else if deliver_frame(state, frame).is_err() {
                fail(state);
                return;
            }
        }
        if batch.ended {
            if state.borrow().subscription_id.is_none() {
                state.borrow_mut().channel_ended = true;
            } else {
                finish_channel_end(state);
            }
        }
    }

    fn deliver_frame(
        state: &Rc<RefCell<ConnectionState>>,
        frame: DesktopStructuredEventFrame,
    ) -> Result<(), ()> {
        let action = {
            let mut state = state.borrow_mut();
            if frame.subscription_id() != state.subscription_id.ok_or(())?
                || frame.stream() != state.expected_stream
                || state.terminal_seen
                || state.wire_sequence.observe(&frame).is_err()
            {
                return Err(());
            }
            match frame {
                DesktopStructuredEventFrame::Event { event, .. } => DeliveryAction::Event(event),
                DesktopStructuredEventFrame::Terminal { reason, .. } => {
                    state.terminal_seen = true;
                    DeliveryAction::Terminal(reason)
                }
            }
        };
        let handlers = state.borrow().handlers.clone();
        match action {
            DeliveryAction::Event(event) => {
                if !(handlers.on_event)(event) {
                    return Err(());
                }
            }
            DeliveryAction::Terminal(reason) => (handlers.on_terminal)(reason),
        }
        Ok(())
    }

    fn finish_channel_end(state: &Rc<RefCell<ConnectionState>>) {
        let valid = {
            let mut state = state.borrow_mut();
            if state.complete || state.failed || state.cancelled {
                return;
            }
            state.channel_ended = true;
            if state.terminal_seen {
                state.complete = true;
                true
            } else {
                false
            }
        };
        if valid {
            unregister_callback(state);
            resolve_finished(state);
        } else {
            fail(state);
        }
    }

    fn fail(state: &Rc<RefCell<ConnectionState>>) {
        let (handler, subscription_id) = {
            let mut state = state.borrow_mut();
            if state.failed || state.complete || state.cancelled {
                return;
            }
            state.failed = true;
            (Rc::clone(&state.handlers.on_error), state.subscription_id)
        };
        unregister_callback(state);
        if let Some(subscription_id) = subscription_id {
            invoke_close(state, subscription_id);
        }
        resolve_finished(state);
        handler();
    }

    fn resolve_finished(state: &Rc<RefCell<ConnectionState>>) {
        let resolver = state.borrow_mut().finish_resolver.take();
        if let Some(resolver) = resolver {
            _ = resolver.call0(&JsValue::UNDEFINED);
        }
    }

    fn unregister_callback(state: &Rc<RefCell<ConnectionState>>) {
        let registration = {
            let mut state = state.borrow_mut();
            if !state.callback_registered {
                return;
            }
            state.callback_registered = false;
            (state.internals.clone(), JsValue::from(state.callback_id))
        };
        _ = registration
            .0
            .unregister_callback
            .call1(&registration.0.object, &registration.1);
    }

    fn invoke_close(state: &Rc<RefCell<ConnectionState>>, subscription_id: u64) {
        let internals = state.borrow().internals.clone();
        let Ok(args) = to_js(serde_json::json!({
            "request": DesktopStructuredSubscriptionCloseRequest { subscription_id },
        })) else {
            return;
        };
        let Ok(promise) = invoke(&internals, DESKTOP_STRUCTURED_CLOSE_COMMAND, &args) else {
            return;
        };
        wasm_bindgen_futures::spawn_local(async move {
            _ = wasm_bindgen_futures::JsFuture::from(promise).await;
        });
    }

    enum ChannelPacket {
        Message { index: u64, message: JsValue },
        End { index: u64 },
    }

    fn parse_channel_packet(payload: &JsValue) -> Result<ChannelPacket, ()> {
        let index = Reflect::get(payload, &JsValue::from_str("index"))
            .map_err(|_| ())?
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
            .and_then(|value| {
                (value <= DESKTOP_STRUCTURED_SUBSCRIPTION_ID_EXCLUSIVE_LIMIT as f64)
                    .then_some(value as u64)
            })
            .ok_or(())?;
        if Reflect::has(payload, &JsValue::from_str("end")).map_err(|_| ())? {
            return Ok(ChannelPacket::End { index });
        }
        let message = Reflect::get(payload, &JsValue::from_str("message")).map_err(|_| ())?;
        Ok(ChannelPacket::Message { index, message })
    }

    fn tauri_internals() -> Result<TauriInternals, ()> {
        let window = web_sys::window().ok_or(())?;
        if Reflect::get(window.as_ref(), &JsValue::from_str(TAURI_RUNTIME_FLAG))
            .map_err(|_| ())?
            .as_bool()
            != Some(true)
        {
            return Err(());
        }
        let object = Reflect::get(
            window.as_ref(),
            &JsValue::from_str(TAURI_INTERNALS_PROPERTY),
        )
        .map_err(|_| ())?;
        Ok(TauriInternals {
            invoke: function(&object, TAURI_INVOKE_PROPERTY)?,
            transform_callback: function(&object, TAURI_TRANSFORM_CALLBACK_PROPERTY)?,
            unregister_callback: function(&object, TAURI_UNREGISTER_CALLBACK_PROPERTY)?,
            object,
        })
    }

    fn function(object: &JsValue, name: &str) -> Result<Function, ()> {
        Reflect::get(object, &JsValue::from_str(name))
            .map_err(|_| ())?
            .dyn_into::<Function>()
            .map_err(|_| ())
    }

    fn invoke(internals: &TauriInternals, command: &str, args: &JsValue) -> Result<Promise, ()> {
        internals
            .invoke
            .call2(&internals.object, &JsValue::from_str(command), args)
            .map_err(|_| ())?
            .dyn_into::<Promise>()
            .map_err(|_| ())
    }

    fn to_js(value: serde_json::Value) -> Result<JsValue, ()> {
        let json = serde_json::to_string(&value).map_err(|_| ())?;
        JSON::parse(&json).map_err(|_| ())
    }

    fn from_js_string(value: &JsValue) -> Result<String, ()> {
        let json = JSON::stringify(value)
            .map_err(|_| ())?
            .as_string()
            .ok_or(())?;
        if json.len() > MAX_STRUCTURED_FRAME_JSON_BYTES {
            return Err(());
        }
        Ok(json)
    }

    fn frame_from_channel_message(value: &JsValue) -> Result<DesktopStructuredEventFrame, ()> {
        let json = value.as_string().ok_or(())?;
        if json.len() > MAX_STRUCTURED_FRAME_JSON_BYTES {
            return Err(());
        }
        serde_json::from_str(&json).map_err(|_| ())
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::{
    DesktopStructuredConnection, DesktopStructuredHandlers, is_tauri_host, open_desktop_structured,
};

#[cfg(test)]
mod tests {
    use openbot_contracts::command::{AppEvent, SubscriptionRequest};
    use openbot_contracts::desktop::{
        DesktopStructuredEventFrame, DesktopStructuredGapCause, DesktopStructuredSequenceGap,
        DesktopStructuredStreamKind, DesktopStructuredTerminalReason,
    };

    use super::*;

    fn event(
        sequence: u64,
        skipped: Option<DesktopStructuredSequenceGap>,
    ) -> DesktopStructuredEventFrame {
        DesktopStructuredEventFrame::Event {
            subscription_id: 1,
            stream: DesktopStructuredStreamKind::Health,
            sequence,
            skipped,
            event: AppEvent::Heartbeat { seq: sequence },
        }
    }

    #[test]
    fn channel_order_restores_out_of_order_messages_before_end() {
        let mut order = OrderedChannel::new();
        assert!(order.push_message(1, "one").unwrap().messages.is_empty());
        let batch = order.push_end(2).unwrap();
        assert!(batch.messages.is_empty());
        assert!(!batch.ended);
        let batch = order.push_message(0, "zero").unwrap();
        assert_eq!(batch.messages, ["zero", "one"]);
        assert!(batch.ended);
    }

    #[test]
    fn channel_order_rejects_duplicates_messages_after_end_and_unbounded_reorder() {
        let mut duplicate = OrderedChannel::new();
        duplicate.push_message(0, 0).unwrap();
        assert_eq!(
            duplicate.push_message(0, 0).unwrap_err(),
            ChannelOrderError::DuplicateOrPast
        );

        let mut ended = OrderedChannel::new();
        ended.push_end(0).unwrap();
        assert_eq!(
            ended.push_message(0, 0).unwrap_err(),
            ChannelOrderError::DuplicateOrPast
        );

        let mut pressure = OrderedChannel::new();
        for index in 1..=MAX_REORDERED_CHANNEL_FRAMES as u64 {
            pressure.push_message(index, index).unwrap();
        }
        assert_eq!(
            pressure
                .push_message(MAX_REORDERED_CHANNEL_FRAMES as u64 + 1, 0)
                .unwrap_err(),
            ChannelOrderError::TooManyPending
        );
    }

    #[test]
    fn wire_sequence_requires_exact_gap_and_terminal_is_last() {
        let mut tracker = WireSequenceTracker::new();
        tracker.observe(&event(0, None)).unwrap();
        tracker
            .observe(&event(
                3,
                Some(DesktopStructuredSequenceGap {
                    from_sequence: 1,
                    through_sequence: 2,
                    cause: DesktopStructuredGapCause::Dropped,
                }),
            ))
            .unwrap();
        let terminal = DesktopStructuredEventFrame::Terminal {
            subscription_id: 1,
            stream: DesktopStructuredStreamKind::Health,
            sequence: 4,
            skipped: None,
            reason: DesktopStructuredTerminalReason::UpstreamEnded,
            overflow_class: None,
        };
        tracker.observe(&terminal).unwrap();
        assert_eq!(
            tracker.observe(&event(5, None)).unwrap_err(),
            WireSequenceError::AfterTerminal
        );

        let mut silent = WireSequenceTracker::new();
        assert_eq!(
            silent.observe(&event(1, None)).unwrap_err(),
            WireSequenceError::SilentLoss
        );
        let mut bad_gap = WireSequenceTracker::new();
        assert_eq!(
            bad_gap
                .observe(&event(
                    2,
                    Some(DesktopStructuredSequenceGap {
                        from_sequence: 0,
                        through_sequence: 0,
                        cause: DesktopStructuredGapCause::Superseded,
                    })
                ))
                .unwrap_err(),
            WireSequenceError::InconsistentGap
        );
    }

    #[test]
    fn request_stream_mapping_is_shared_with_contracts() {
        assert_eq!(
            DesktopStructuredStreamKind::from_request(&SubscriptionRequest::ChannelActivity),
            DesktopStructuredStreamKind::ChannelActivity
        );
    }

    #[test]
    fn pinned_tauri_internal_surface_is_narrow_and_exact() {
        assert_eq!(TAURI_RUNTIME_FLAG, "isTauri");
        assert_eq!(TAURI_INTERNALS_PROPERTY, "__TAURI_INTERNALS__");
        assert_eq!(TAURI_INVOKE_PROPERTY, "invoke");
        assert_eq!(TAURI_TRANSFORM_CALLBACK_PROPERTY, "transformCallback");
        assert_eq!(TAURI_UNREGISTER_CALLBACK_PROPERTY, "unregisterCallback");
    }

    #[test]
    fn all_three_realtime_owners_select_tauri_and_keep_the_web_fallback() {
        let cases = [
            (
                include_str!("shell/app_sidebar/channels.rs"),
                "SubscriptionRequest::ChannelActivity",
                "WebSocket::open_with_protocol",
            ),
            (
                include_str!("features/approvals/component.rs"),
                "SubscriptionRequest::ToolApprovalActivity",
                "WebSocket::open_with_protocol",
            ),
            (
                include_str!("features/channels/conversation.rs"),
                "SubscriptionRequest::ThreadEvents",
                "EventSource::new",
            ),
        ];
        for (source, request, web_fallback) in cases {
            assert!(source.contains("is_tauri_host()"));
            assert!(source.contains("open_desktop_structured"));
            assert!(source.contains(request));
            assert!(source.contains(web_fallback));
        }
    }
}
