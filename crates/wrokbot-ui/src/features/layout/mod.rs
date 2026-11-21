//! Configuration-page layout components shared by Web and Desktop hosts.

pub mod detail_panel;
pub(crate) mod editor_location;
pub(crate) mod library_editor;
pub mod page_shell;
pub mod row_mark;
pub mod section_tabs;
pub mod stagger;

pub use detail_panel::{DetailPanel, DetailPanelLayout, DetailPanelMain};
pub use page_shell::{
    PageActions, PageEmpty, PageHeader, PageRows, PageSection, PageShell, PageWidth,
};
pub use row_mark::RowMark;
pub(crate) use section_tabs::SectionTab;
pub use section_tabs::SectionTabs;
pub use stagger::StaggerItem;
