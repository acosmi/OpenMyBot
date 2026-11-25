//! Same-origin ScreenSession viewer with one active image and one replaceable latest JPEG.
//! Image load completion is a display receipt, not a measured compositor paint timestamp.
//! No ticket URL, renderer-issued input, authority guesses or unbounded frame queue.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
use crate::{
    features::computer::ComputerPlaceholder,
    i18n::{Locale, t, t_string, use_i18n},
    primitives::{Button, ButtonSize, ButtonVariant, timestamp::localized_date_time},
};
use leptos::prelude::*;
use openbot_contracts::screen::ScreenSessionTarget;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScreenStatus {
    Waiting,
    Connecting,
    Live,
    Disconnected,
    Stalled,
    Invalidated,
    Unavailable,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ImageIdentity {
    connection: u64,
    sequence: u64,
}
#[derive(Clone)]
struct ViewerImage {
    identity: ImageIdentity,
    src: String,
    captured_at_ms: i64,
}

struct ScreenImagePayload {
    jpeg: Vec<u8>,
    captured_at_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LoadedSourceFrame {
    identity: ImageIdentity,
    captured_at_ms: i64,
}

fn image_callback_matches(
    connection: Option<u64>,
    closed: bool,
    current: Option<ImageIdentity>,
    completed: ImageIdentity,
) -> bool {
    !closed && connection == Some(completed.connection) && current == Some(completed)
}

#[derive(Clone, Copy)]
struct ViewerState {
    status: RwSignal<ScreenStatus>,
    image: RwSignal<Option<ViewerImage>>,
    connection: RwSignal<u64>,
    generation: RwSignal<u64>,
    sequence: RwSignal<u64>,
    received_sequence: RwSignal<u64>,
    received_at_ms: RwSignal<f64>,
    displayed_at_ms: RwSignal<f64>,
    loaded_source: RwSignal<Option<LoadedSourceFrame>>,
    #[cfg(target_arch = "wasm32")]
    renderer: StoredValue<Option<std::rc::Rc<ImageRenderer>>, LocalStorage>,
}
impl ViewerState {
    fn new() -> Self {
        Self {
            status: RwSignal::new(ScreenStatus::Waiting),
            image: RwSignal::new(None),
            connection: RwSignal::new(0),
            generation: RwSignal::new(0),
            sequence: RwSignal::new(0),
            received_sequence: RwSignal::new(0),
            received_at_ms: RwSignal::new(0.0),
            displayed_at_ms: RwSignal::new(0.0),
            loaded_source: RwSignal::new(None),
            #[cfg(target_arch = "wasm32")]
            renderer: StoredValue::new_local(None),
        }
    }

    fn clear(self, status: ScreenStatus) {
        self.status.set(status);
        self.image.set(None);
        self.loaded_source.set(None);
        self.generation.set(0);
        self.sequence.set(0);
        self.received_sequence.set(0);
        self.received_at_ms.set(0.0);
        self.displayed_at_ms.set(0.0);
    }

    fn clear_connection(self, connection: u64, status: Option<ScreenStatus>) -> bool {
        if self.connection.try_get_untracked() != Some(connection) {
            return false;
        }
        self.clear(status.unwrap_or_else(|| self.status.get_untracked()));
        true
    }

    fn source_for_completion(
        self,
        connection: u64,
        closed: bool,
        identity: ImageIdentity,
    ) -> Option<LoadedSourceFrame> {
        let image = self.image.try_get_untracked().flatten()?;
        (connection == identity.connection
            && image_callback_matches(
                self.connection.try_get_untracked(),
                closed,
                Some(image.identity),
                identity,
            ))
        .then_some(LoadedSourceFrame {
            identity,
            captured_at_ms: image.captured_at_ms,
        })
    }

    fn confirm_loaded(
        self,
        source: LoadedSourceFrame,
        displayed: super::latest_frame::DisplayedFrame,
    ) -> bool {
        if displayed.received.sequence != source.identity.sequence
            || self.source_for_completion(source.identity.connection, false, source.identity)
                != Some(source)
        {
            return false;
        }
        self.sequence.set(displayed.received.sequence);
        self.displayed_at_ms.set(displayed.loaded_at_ms);
        self.loaded_source.set(Some(source));
        self.status.set(ScreenStatus::Live);
        true
    }

    /// The next decode may already have replaced the DOM image after the preceding load.
    /// Only an exact loaded identity can contribute the current image's source timestamp.
    fn visible_source(self) -> Option<LoadedSourceFrame> {
        let source = self.loaded_source.get()?;
        let image = self.image.get()?;
        (source.identity.connection == self.connection.get()
            && source.identity.sequence == self.sequence.get()
            && source.identity == image.identity
            && source.captured_at_ms == image.captured_at_ms)
            .then_some(source)
    }

    #[cfg(target_arch = "wasm32")]
    fn image_completed(self, identity: ImageIdentity, failed: bool) {
        let renderer = self.renderer.with_value(Clone::clone);
        if let Some(renderer) = renderer
            && renderer.connection == identity.connection
        {
            if failed {
                renderer.image_failed(identity);
            } else {
                renderer.image_loaded(identity);
            }
        }
    }
}

#[component]
pub(crate) fn ScreenViewer(
    target: Signal<Option<ScreenSessionTarget>>,
    active: Signal<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    let state = ViewerState::new();
    let reload = RwSignal::new(0_u64);
    install_viewer(target, active, reload, state);
    let can_retry = Signal::derive(move || {
        target.get().is_some()
            && matches!(
                state.status.get(),
                ScreenStatus::Failed
                    | ScreenStatus::Disconnected
                    | ScreenStatus::Invalidated
                    | ScreenStatus::Stalled
            )
    });
    view! {
        <Show when=move || state.image.get().is_some() fallback=move || view! { <ComputerPlaceholder/> }>
            <div class="ob-computer-placeholder" data-frame-generation=move || state.generation.get() data-frame-sequence=move || state.sequence.get()
                data-frame-received-sequence=move || state.received_sequence.get() data-frame-received-at-ms=move || state.received_at_ms.get()
                data-frame-loaded-at-ms=move || state.displayed_at_ms.get()>
                <For each={move || state.image.get().into_iter().collect::<Vec<_>>()} key=|image| image.identity children=move |image| {
                    let identity = image.identity;
                    view! { <img class="ob-computer-placeholder-art object-contain" src=image.src alt=move || t_string!(i18n, computer.screen).to_owned()
                    on:load=move |_| {
                        #[cfg(target_arch = "wasm32")]
                        state.image_completed(identity, false);
                        #[cfg(not(target_arch = "wasm32"))] let _ = identity;
                    }
                    on:error=move |_| {
                        #[cfg(target_arch = "wasm32")]
                        state.image_completed(identity, true);
                        #[cfg(not(target_arch = "wasm32"))] let _ = identity;
                    }/> }
                }/>
            </div>
            <p class="ob-page-intro" data-screen-frame-caption="">{move || match state.visible_source() {
                Some(source) => match format_source_capture(source.captured_at_ms, i18n.get_locale()) {
                    Some((datetime, label)) => view! {
                        <span>{move || t!(i18n, computer.screen_last_loaded)} " · " {move || t!(i18n, computer.screen_source_capture)} " "
                            <time datetime=datetime data-frame-source-connection=source.identity.connection
                                data-frame-source-sequence=source.identity.sequence data-frame-source-captured-at-ms=source.captured_at_ms>{label}</time>
                        </span>
                    }.into_any(),
                    None => view! { <span>{move || t!(i18n, computer.screen_last_loaded)} " · " {move || t!(i18n, computer.screen_source_time_unavailable)}</span> }.into_any(),
                },
                None => view! { <span>{move || t!(i18n, computer.screen_frame_loading)}</span> }.into_any(),
            }}</p>
        </Show>
        <p class="ob-page-intro" role="status">{move || match state.status.get() {
            ScreenStatus::Waiting => t_string!(i18n, computer.no_target_body).to_owned(),
            ScreenStatus::Connecting => t_string!(i18n, computer.screen_connecting).to_owned(),
            ScreenStatus::Live => t_string!(i18n, computer.screen_live).to_owned(),
            ScreenStatus::Stalled => t_string!(i18n, computer.screen_stalled).to_owned(),
            ScreenStatus::Disconnected => t_string!(i18n, computer.screen_disconnected).to_owned(),
            ScreenStatus::Invalidated => t_string!(i18n, computer.screen_invalidated).to_owned(),
            ScreenStatus::Unavailable => t_string!(i18n, computer.screen_unavailable).to_owned(),
            ScreenStatus::Failed => t_string!(i18n, computer.screen_failed).to_owned(),
        }}</p>
        <Show when=move || can_retry.get()><Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| { reload.update(|n| *n = n.saturating_add(1)); }>{move || t!(i18n, common.retry)}</Button></Show>
    }
}

fn format_source_capture(ms: i64, locale: Locale) -> Option<(String, String)> {
    let at = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .filter(|_| ms > 0)?;
    Some((
        at.format(&time::format_description::well_known::Rfc3339)
            .ok()?,
        localized_date_time(at, locale),
    ))
}

fn screen_url(origin: &str) -> Option<String> {
    let mut url = url::Url::parse(origin).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme).ok()?;
    url.set_path("/api/screen");
    Some(url.to_string())
}

fn install_viewer(
    target: Signal<Option<ScreenSessionTarget>>,
    active: Signal<bool>,
    reload: RwSignal<u64>,
    state: ViewerState,
) {
    #[cfg(target_arch = "wasm32")]
    {
        let visible = RwSignal::new(true);
        let visibility = StoredValue::new_local(VisibilityListener::new(visible));
        on_cleanup(move || {
            visibility.update_value(|value| {
                value.take();
            })
        });
        Effect::new(move |_| {
            reload.track();
            let selected = target.get();
            let enabled = active.get() && visible.get();
            let Some(connection_id) = state.connection.get_untracked().checked_add(1) else {
                state.clear(ScreenStatus::Failed);
                return;
            };
            state.connection.set(connection_id);
            state.clear(ScreenStatus::Waiting);
            if !enabled {
                return;
            }
            let Some(selected) = selected else {
                return;
            };
            if crate::api::desktop_transport::is_tauri_host() {
                state.clear(ScreenStatus::Unavailable);
                return;
            }
            let connection = StoredValue::new_local(None::<ScreenConnection>);
            on_cleanup(move || {
                connection.update_value(|value| {
                    value.take();
                });
                state.renderer.update_value(|renderer| {
                    if renderer
                        .as_ref()
                        .is_some_and(|renderer| renderer.connection == connection_id)
                    {
                        renderer.take();
                    }
                });
            });
            state.status.set(ScreenStatus::Connecting);
            state.generation.set(selected.computer_generation.get());
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match connect_screen(selected, state, connection_id).await {
                    Ok(socket) => {
                        let renderer = socket.renderer.clone();
                        state.renderer.set_value(Some(renderer.clone()));
                        connection.set_value(Some(socket));
                        loop {
                            let promise = js_sys::Promise::new(&mut |resolve, _| {
                                if let Some(window) = web_sys::window() {
                                    _ = window
                                        .set_timeout_with_callback_and_timeout_and_arguments_0(
                                            &resolve, 250,
                                        );
                                }
                            });
                            _ = wasm_bindgen_futures::JsFuture::from(promise).await;
                            if !renderer.is_current() {
                                connection.update_value(|value| {
                                    value.take();
                                });
                                break;
                            }
                            if renderer.progress_timed_out() {
                                renderer.close(Some(ScreenStatus::Stalled));
                                connection.update_value(|value| {
                                    value.take();
                                });
                                break;
                            }
                        }
                    }
                    Err(status) => {
                        if state.connection.try_get_untracked() == Some(connection_id) {
                            state.clear(status);
                        }
                    }
                }
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (target, active, reload);
        state.clear(ScreenStatus::Unavailable);
    }
}

#[cfg(target_arch = "wasm32")]
struct VisibilityListener {
    document: web_sys::Document,
    callback: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::Event)>,
}
#[cfg(target_arch = "wasm32")]
impl VisibilityListener {
    fn new(visible: RwSignal<bool>) -> Option<Self> {
        use wasm_bindgen::JsCast as _;
        let document = web_sys::window()?.document()?;
        visible.set(document.visibility_state() == web_sys::VisibilityState::Visible);
        let observed = document.clone();
        let callback = wasm_bindgen::closure::Closure::wrap(Box::new(move |_: web_sys::Event| {
            visible.set(observed.visibility_state() == web_sys::VisibilityState::Visible);
        }) as Box<dyn FnMut(_)>);
        document
            .add_event_listener_with_callback("visibilitychange", callback.as_ref().unchecked_ref())
            .ok()?;
        Some(Self { document, callback })
    }
}
#[cfg(target_arch = "wasm32")]
impl Drop for VisibilityListener {
    fn drop(&mut self) {
        use wasm_bindgen::JsCast as _;
        _ = self.document.remove_event_listener_with_callback(
            "visibilitychange",
            self.callback.as_ref().unchecked_ref(),
        );
    }
}

#[cfg(target_arch = "wasm32")]
struct ObjectUrls {
    current: Option<String>,
}
#[cfg(target_arch = "wasm32")]
impl ObjectUrls {
    fn replace(&mut self, next: Option<String>) {
        if let Some(old) = self.current.take() {
            _ = web_sys::Url::revoke_object_url(&old);
        }
        self.current = next;
    }
}
#[cfg(target_arch = "wasm32")]
impl Drop for ObjectUrls {
    fn drop(&mut self) {
        self.replace(None);
    }
}

#[cfg(target_arch = "wasm32")]
struct ImageRenderer {
    state: ViewerState,
    connection: u64,
    socket: web_sys::WebSocket,
    frames: std::cell::RefCell<super::latest_frame::LatestFrame<ScreenImagePayload>>,
    urls: std::cell::RefCell<ObjectUrls>,
    connected_at_ms: f64,
    closed: std::cell::Cell<bool>,
}
#[cfg(target_arch = "wasm32")]
impl ImageRenderer {
    fn is_current(&self) -> bool {
        !self.closed.get() && self.state.connection.try_get_untracked() == Some(self.connection)
    }

    fn owns_image(&self, identity: ImageIdentity) -> bool {
        identity.connection == self.connection
            && image_callback_matches(
                self.state.connection.try_get_untracked(),
                self.closed.get(),
                self.state
                    .image
                    .try_get_untracked()
                    .flatten()
                    .map(|image| image.identity),
                identity,
            )
    }

    fn last_received_sequence(&self) -> u64 {
        self.frames
            .borrow()
            .received()
            .map_or(0, |frame| frame.sequence)
    }

    fn receive(&self, sequence: u64, captured_at_ms: i64, jpeg: &[u8]) {
        if !self.is_current() {
            return;
        }
        let now = monotonic_ms();
        let accepted = self.frames.borrow_mut().receive(
            sequence,
            now,
            ScreenImagePayload {
                jpeg: jpeg.to_vec(),
                captured_at_ms,
            },
        );
        let Ok(next) = accepted else {
            self.close(Some(ScreenStatus::Failed));
            return;
        };
        self.state.received_sequence.set(sequence);
        self.state.received_at_ms.set(now);
        if let Some(frame) = next {
            self.start_image(frame);
        }
    }

    fn start_image(&self, frame: super::latest_frame::Frame<ScreenImagePayload>) {
        if !self.is_current() {
            return;
        }
        let data = js_sys::Uint8Array::from(frame.payload.jpeg.as_slice());
        let parts = js_sys::Array::new();
        parts.push(&data);
        let options = web_sys::BlobPropertyBag::new();
        options.set_type("image/jpeg");
        let url = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &options)
            .and_then(|blob| web_sys::Url::create_object_url_with_blob(&blob));
        let Ok(src) = url else {
            self.close(Some(ScreenStatus::Failed));
            return;
        };
        self.urls.borrow_mut().replace(Some(src.clone()));
        self.state.image.set(Some(ViewerImage {
            identity: ImageIdentity {
                connection: self.connection,
                sequence: frame.received.sequence,
            },
            src,
            captured_at_ms: frame.payload.captured_at_ms,
        }));
    }

    fn image_loaded(&self, identity: ImageIdentity) {
        let Some(source) =
            self.state
                .source_for_completion(self.connection, self.closed.get(), identity)
        else {
            return;
        };
        let completed = self
            .frames
            .borrow_mut()
            .complete(identity.sequence, monotonic_ms());
        let Some(completed) = completed else {
            return;
        };
        if !self.state.confirm_loaded(source, completed.displayed) {
            return;
        }
        if let Some(next) = completed.next {
            self.start_image(next);
        }
    }

    fn image_failed(&self, identity: ImageIdentity) {
        if self.owns_image(identity) {
            self.close(Some(ScreenStatus::Failed));
        }
    }

    fn progress_timed_out(&self) -> bool {
        self.frames
            .borrow()
            .progress_timed_out(self.connected_at_ms, monotonic_ms())
    }

    fn close(&self, status: Option<ScreenStatus>) {
        if self.closed.replace(true) {
            return;
        }
        self.frames.borrow_mut().close();
        self.urls.borrow_mut().replace(None);
        self.state.clear_connection(self.connection, status);
        _ = self.socket.close();
    }
}

#[cfg(target_arch = "wasm32")]
struct ScreenConnection {
    socket: web_sys::WebSocket,
    _message: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::MessageEvent)>,
    _close: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::CloseEvent)>,
    _error: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::Event)>,
    renderer: std::rc::Rc<ImageRenderer>,
}
#[cfg(target_arch = "wasm32")]
impl Drop for ScreenConnection {
    fn drop(&mut self) {
        self.socket.set_onmessage(None);
        self.socket.set_onclose(None);
        self.socket.set_onerror(None);
        self.renderer.close(None);
    }
}

#[cfg(target_arch = "wasm32")]
async fn connect_screen(
    target: ScreenSessionTarget,
    state: ViewerState,
    connection: u64,
) -> Result<ScreenConnection, ScreenStatus> {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    use wasm_bindgen::{JsCast as _, closure::Closure};
    use web_sys::{RequestCache, RequestCredentials, RequestRedirect};
    let origin = web_sys::window()
        .ok_or(ScreenStatus::Unavailable)?
        .location()
        .origin()
        .map_err(|_| ScreenStatus::Unavailable)?;
    let url = screen_url(&origin).ok_or(ScreenStatus::Unavailable)?;
    let response = gloo_net::http::Request::post("/api/screen/sessions")
        .cache(RequestCache::NoStore)
        .credentials(RequestCredentials::SameOrigin)
        .redirect(RequestRedirect::Error)
        .json(&target)
        .map_err(|_| ScreenStatus::Failed)?
        .send()
        .await
        .map_err(|_| ScreenStatus::Failed)?;
    if response.status() != 200 {
        return Err(match response.status() {
            401 | 403 | 404 => ScreenStatus::Invalidated,
            503 => ScreenStatus::Unavailable,
            _ => ScreenStatus::Failed,
        });
    }
    let ticket = response
        .json::<openbot_contracts::screen::ScreenSessionTicket>()
        .await
        .map_err(|_| ScreenStatus::Failed)?;
    if state.connection.try_get_untracked() != Some(connection) {
        return Err(ScreenStatus::Invalidated);
    }
    let Some(token) = ticket.ticket_protocol().strip_prefix("obot_screen_") else {
        return Err(ScreenStatus::Failed);
    };
    if ticket.base_protocol() != "openbot.screen.v1"
        || token.len() != 32
        || !token.bytes().all(|b| b.is_ascii_hexdigit())
        || (ticket.expires_at_ms() as f64) <= js_sys::Date::now()
    {
        return Err(ScreenStatus::Invalidated);
    }
    let protocols = js_sys::Array::new();
    protocols.push(&ticket.base_protocol().into());
    protocols.push(&ticket.ticket_protocol().into());
    let socket = web_sys::WebSocket::new_with_str_sequence(&url, &protocols)
        .map_err(|_| ScreenStatus::Failed)?;
    drop(ticket); // never retained in renderer signals, URL, logs, or retry state
    socket.set_binary_type(web_sys::BinaryType::Arraybuffer);
    let renderer = Rc::new(ImageRenderer {
        state,
        connection,
        socket: socket.clone(),
        frames: RefCell::new(super::latest_frame::LatestFrame::default()),
        urls: RefCell::new(ObjectUrls { current: None }),
        connected_at_ms: monotonic_ms(),
        closed: Cell::new(false),
    });
    let message_renderer = renderer.clone();
    let generation = target.computer_generation.get();
    let message = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
        if !message_renderer.is_current() {
            return;
        }
        let reject = || message_renderer.close(Some(ScreenStatus::Failed));
        if message_renderer.socket.protocol() != "openbot.screen.v1" {
            reject();
            return;
        }
        let Ok(buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() else {
            reject();
            return;
        };
        if buffer.byte_length() as usize > openbot_contracts::engine::MAX_ENGINE_IMAGE_BYTES + 68 {
            reject();
            return;
        }
        let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
        let Ok(frame) = super::frame::decode_frame(
            &bytes,
            generation,
            message_renderer.last_received_sequence(),
        ) else {
            reject();
            return;
        };
        message_renderer.receive(frame.sequence, frame.captured_at_ms, frame.jpeg);
    }) as Box<dyn FnMut(_)>);
    socket.set_onmessage(Some(message.as_ref().unchecked_ref()));
    let close_renderer = renderer.clone();
    let close = Closure::wrap(Box::new(move |event: web_sys::CloseEvent| {
        close_renderer.close(Some(if event.code() == 1008 {
            ScreenStatus::Invalidated
        } else {
            ScreenStatus::Disconnected
        }));
    }) as Box<dyn FnMut(_)>);
    socket.set_onclose(Some(close.as_ref().unchecked_ref()));
    let error_renderer = renderer.clone();
    let error = Closure::wrap(Box::new(move |_: web_sys::Event| {
        error_renderer.close(Some(ScreenStatus::Failed));
    }) as Box<dyn FnMut(_)>);
    socket.set_onerror(Some(error.as_ref().unchecked_ref()));
    Ok(ScreenConnection {
        socket,
        _message: message,
        _close: close,
        _error: error,
        renderer,
    })
}

#[cfg(target_arch = "wasm32")]
fn monotonic_ms() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map_or_else(js_sys::Date::now, |p| p.now())
}

#[cfg(test)]
mod tests {
    use super::super::latest_frame::{Frame, LatestFrame};
    use super::*;

    fn payload(captured_at_ms: i64) -> ScreenImagePayload {
        ScreenImagePayload {
            jpeg: vec![1, 2, 3],
            captured_at_ms,
        }
    }

    fn install_image(
        state: ViewerState,
        connection: u64,
        frame: Frame<ScreenImagePayload>,
    ) -> ImageIdentity {
        let identity = ImageIdentity {
            connection,
            sequence: frame.received.sequence,
        };
        state.image.set(Some(ViewerImage {
            identity,
            src: format!("fixture-{}-{}", connection, identity.sequence),
            captured_at_ms: frame.payload.captured_at_ms,
        }));
        identity
    }

    #[test]
    fn source_time_waits_for_exact_final_pending_image_load() {
        Owner::new().with(|| {
            let state = ViewerState::new();
            state.connection.set(1);
            let mut frames = LatestFrame::default();
            let first = frames.receive(1, 10.0, payload(1_000)).unwrap().unwrap();
            let first = install_image(state, 1, first);
            assert_eq!(state.visible_source(), None);
            assert!(frames.receive(2, 20.0, payload(2_000)).unwrap().is_none());
            assert!(frames.receive(3, 25.0, payload(3_000)).unwrap().is_none());
            let final_identity = ImageIdentity {
                connection: 1,
                sequence: 3,
            };
            assert_eq!(state.source_for_completion(1, false, final_identity), None);
            assert!(frames.complete(3, 26.0).is_none());

            let first_source = state.source_for_completion(1, false, first).unwrap();
            let completed = frames.complete(1, 30.0).unwrap();
            assert!(state.confirm_loaded(first_source, completed.displayed));
            assert_eq!(state.visible_source().unwrap().captured_at_ms, 1_000);
            let next = completed.next.unwrap();
            assert_eq!(next.received.sequence, 3);
            assert_eq!(next.payload.captured_at_ms, 3_000);
            let final_image = install_image(state, 1, next);
            // The preceding loaded receipt remains A, while the actual DOM image is now C.
            assert_eq!(state.sequence.get_untracked(), 1);
            assert_eq!(state.loaded_source.get_untracked(), Some(first_source));
            assert_eq!(state.visible_source(), None);
            assert_eq!(state.source_for_completion(1, false, first), None);
            assert!(!state.confirm_loaded(first_source, completed.displayed));
            assert!(frames.complete(1, 31.0).is_none());

            // No further receive is needed to load and confirm the final pending image.
            let final_source = state.source_for_completion(1, false, final_image).unwrap();
            let completed = frames.complete(3, 40.0).unwrap();
            assert!(completed.next.is_none());
            assert!(state.confirm_loaded(final_source, completed.displayed));
            assert_eq!(
                state.visible_source(),
                Some(LoadedSourceFrame {
                    identity: final_identity,
                    captured_at_ms: 3_000,
                })
            );
            assert_eq!(state.displayed_at_ms.get_untracked(), 40.0);
        });
    }

    #[test]
    fn cleared_source_time_cannot_return_from_old_connection_with_same_sequence() {
        Owner::new().with(|| {
            let state = ViewerState::new();
            state.connection.set(1);
            let mut old_frames = LatestFrame::default();
            let old_frame = old_frames
                .receive(7, 10.0, payload(1_000))
                .unwrap()
                .unwrap();
            let old_image = install_image(state, 1, old_frame);
            let old_source = state.source_for_completion(1, false, old_image).unwrap();
            let old_completed = old_frames.complete(7, 20.0).unwrap();
            assert!(state.confirm_loaded(old_source, old_completed.displayed));
            assert_eq!(state.visible_source(), Some(old_source));

            // A target change increments the connection before clearing the old projection.
            state.connection.set(2);
            state.clear(ScreenStatus::Waiting);
            old_frames.close();
            assert_eq!(state.loaded_source.get_untracked(), None);
            assert!(state.image.get_untracked().is_none());
            assert_eq!(state.visible_source(), None);
            assert!(old_frames.complete(7, 30.0).is_none());
            assert!(old_frames.receive(8, 30.0, payload(1_500)).is_err());

            let mut new_frames = LatestFrame::default();
            let new_frame = new_frames
                .receive(7, 40.0, payload(2_000))
                .unwrap()
                .unwrap();
            let new_image = install_image(state, 2, new_frame);
            assert_eq!(state.source_for_completion(1, false, old_image), None);
            assert_eq!(state.source_for_completion(2, true, new_image), None);
            assert!(!state.confirm_loaded(old_source, old_completed.displayed));
            assert_eq!(state.visible_source(), None);
            let new_source = state.source_for_completion(2, false, new_image).unwrap();
            let new_completed = new_frames.complete(7, 50.0).unwrap();
            assert!(state.confirm_loaded(new_source, new_completed.displayed));
            assert_eq!(state.visible_source().unwrap().captured_at_ms, 2_000);
            assert!(!state.confirm_loaded(old_source, old_completed.displayed));
            assert!(!state.clear_connection(1, Some(ScreenStatus::Disconnected)));
            assert_eq!(state.visible_source(), Some(new_source));

            assert!(state.clear_connection(2, Some(ScreenStatus::Disconnected)));
            assert_eq!(state.loaded_source.get_untracked(), None);
            assert!(state.image.get_untracked().is_none());
            assert_eq!(state.visible_source(), None);
            assert_eq!(state.source_for_completion(2, false, new_image), None);
        });
    }

    #[test]
    fn image_callbacks_are_bound_to_connection_and_exact_image() {
        let old = ImageIdentity {
            connection: 1,
            sequence: 7,
        };
        let next = ImageIdentity {
            connection: 2,
            sequence: 7,
        };
        let newer = ImageIdentity {
            connection: 2,
            sequence: 8,
        };
        assert!(image_callback_matches(Some(2), false, Some(next), next));
        assert!(!image_callback_matches(Some(2), false, Some(next), old));
        assert!(!image_callback_matches(Some(2), false, Some(newer), next));
        assert!(!image_callback_matches(Some(2), true, Some(next), next));
        assert!(!image_callback_matches(Some(2), false, None, next));
        assert!(!image_callback_matches(None, false, Some(next), next));
    }

    #[test]
    fn screen_connection_url_never_contains_a_ticket_or_query() {
        assert_eq!(
            screen_url("https://example.test"),
            Some("wss://example.test/api/screen".into())
        );
        assert_eq!(
            screen_url("http://127.0.0.1:39027"),
            Some("ws://127.0.0.1:39027/api/screen".into())
        );
        for origin in [
            "https://user@example.test",
            "https://example.test/?ticket=secret",
            "https://example.test/#fragment",
            "file:///private/path",
            "https://example.test/path",
        ] {
            assert!(screen_url(origin).is_none());
        }
    }
}

#[cfg(feature = "design-gallery")]
#[component]
pub(crate) fn ScreenFixturePreview() -> impl IntoView {
    use openbot_contracts::ids::{ComputerGeneration, ComputerId, TabId};
    let mode = RwSignal::new("valid".to_owned());
    let enabled = RwSignal::new(false);
    let target = Signal::derive(move || {
        Some(ScreenSessionTarget {
            computer_id: ComputerId::new("screen-fixture"),
            computer_generation: ComputerGeneration::new(7),
            tab_id: TabId::new(mode.get()),
        })
    });
    view! { <section class="ob-page" id="screen-fixture-preview"><h2>"Screen transport fixture"</h2><p>"Development fixture only. No production computer is connected."</p>
        <Button on_activate=move |_| enabled.update(|v| *v = !*v)>{move || if enabled.get() {"Pause viewer"}else{"Start viewer"}}</Button>
        <div class="ob-skill-chips">{["valid","oversize","stale-generation","stall"].into_iter().map(|name|view! {<Button variant=ButtonVariant::Ghost on_activate=move |_| {mode.set(name.to_owned());enabled.set(true);}>{name}</Button>}).collect_view()}</div>
        <ScreenViewer target active=Signal::derive(move || enabled.get())/>
    </section> }
}
