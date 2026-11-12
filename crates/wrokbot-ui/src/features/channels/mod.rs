//! Channel destination route slices.

pub(crate) mod artifacts;
pub mod composer;
pub mod conversation;
pub mod detail;
pub(crate) mod markdown;
pub(crate) mod message_actions;
pub mod new;
pub mod recipient_field;
pub(crate) mod run_observation;

pub use conversation::ChannelConversation;
pub use detail::ChannelDetailPage;
pub use new::ChannelNewPage;
pub use recipient_field::RecipientField;
