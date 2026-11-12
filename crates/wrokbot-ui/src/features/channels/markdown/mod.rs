//! Bounded, inert Markdown views. Each streaming message owns and drops its cache.
#![cfg_attr(not(test), allow(dead_code))]
mod memo;
mod parser;
mod sanitize;
mod syntax;

use crate::{
    i18n::{t, t_string, use_i18n},
    primitives::CopyButton,
};
use leptos::prelude::*;
use parser::{MarkdownBlock, MarkdownInline, TableAlignment};
use sanitize::{ImagePolicy, SafeUrl};

#[component]
pub(crate) fn MarkdownBody(content: String) -> impl IntoView {
    view! { <div class="ob-markdown">{parser::parse_markdown(&content).into_iter().map(block_view).collect_view()}</div> }
}

#[component]
pub(crate) fn StreamingMarkdownBody(content: Signal<String>) -> impl IntoView {
    let cache = StoredValue::new(memo::StreamingMemoStore::new());
    let blocks = Memo::new(move |_| {
        let mut result = Vec::new();
        cache.update_value(|cache| result = cache.process_stream("stream", &content.get()));
        result
    });
    view! { <div class="ob-markdown" data-streaming="true"><For each=move || blocks.get() key=|block| block.view_key() children=move |entry| block_view((*entry.block).clone())/></div> }
}

fn inline_views(children: Vec<MarkdownInline>) -> impl IntoView {
    children.into_iter().map(inline_view).collect_view()
}
fn blocks_view(children: Vec<MarkdownBlock>) -> impl IntoView {
    children.into_iter().map(block_view).collect_view()
}
fn block_view(block: MarkdownBlock) -> AnyView {
    let i18n = use_i18n();
    match block {
        MarkdownBlock::Paragraph(children) => view! { <p>{inline_views(children)}</p> }.into_any(),
        MarkdownBlock::Heading { level, children } => match level {
            1 | 2 => view! { <h2>{inline_views(children)}</h2> }.into_any(),
            3 => view! { <h3>{inline_views(children)}</h3> }.into_any(),
            _ => view! { <h4>{inline_views(children)}</h4> }.into_any(),
        },
        MarkdownBlock::BlockQuote(children) => view! { <blockquote>{blocks_view(children)}</blockquote> }.into_any(),
        MarkdownBlock::CodeBlock { lang, code } => view! { <CodeBlock lang code/> }.into_any(),
        MarkdownBlock::List { ordered, start, items } => {
            let items = items.into_iter().map(|item| view! { <li data-task=item.task.map(|_| "")>
                {item.task.map(|checked| view! { <span role="img" aria-label=move || if checked { t_string!(i18n, channels.md_checked).to_owned() } else { t_string!(i18n, channels.md_unchecked).to_owned() }>{if checked { "☑ " } else { "☐ " }}</span> })}
                {blocks_view(item.children)}
            </li> }).collect_view();
            if ordered { view! { <ol start=start.unwrap_or(1)>{items}</ol> }.into_any() }
            else { view! { <ul>{items}</ul> }.into_any() }
        },
        MarkdownBlock::Table { alignments, headers, rows } => {
            let header_align = alignments.clone();
            view! { <div class="ob-markdown-table" role="region" tabindex="0" aria-label=move || t_string!(i18n, channels.md_table).to_owned()><table>
                <thead><tr>{headers.into_iter().enumerate().map(|(i, cell)| view! { <th scope="col" data-align=alignment(header_align.get(i))>{inline_views(cell.children)}</th> }).collect_view()}</tr></thead>
                <tbody>{rows.into_iter().map(|row| view! { <tr>{row.into_iter().enumerate().map(|(i, cell)| view! { <td data-align=alignment(alignments.get(i))>{inline_views(cell.children)}</td> }).collect_view()}</tr> }).collect_view()}</tbody>
            </table></div> }.into_any()
        },
        MarkdownBlock::Rule => view! { <hr/> }.into_any(),
        MarkdownBlock::HtmlRaw(raw) => view! { <pre class="ob-transcript-text">{raw}</pre> }.into_any(),
        MarkdownBlock::Limited { preview, .. } => view! { <div><p role="status">{move || t!(i18n, channels.md_limited)}</p><pre class="ob-transcript-text">{preview}</pre></div> }.into_any(),
    }
}
fn alignment(value: Option<&TableAlignment>) -> &'static str {
    match value {
        Some(TableAlignment::Center) => "center",
        Some(TableAlignment::Right) => "right",
        _ => "left",
    }
}
fn inline_view(inline: MarkdownInline) -> AnyView {
    match inline {
        MarkdownInline::Text(text) | MarkdownInline::HtmlRaw(text) => {
            view! { <span>{text}</span> }.into_any()
        }
        MarkdownInline::Emphasis(children) => {
            view! { <em>{inline_views(children)}</em> }.into_any()
        }
        MarkdownInline::Strong(children) => {
            view! { <strong>{inline_views(children)}</strong> }.into_any()
        }
        MarkdownInline::Strikethrough(children) => {
            view! { <del>{inline_views(children)}</del> }.into_any()
        }
        MarkdownInline::Code(code) => view! { <code>{code}</code> }.into_any(),
        MarkdownInline::Link {
            url,
            title,
            children,
        } => link_view(url, title, inline_views(children).into_any()),
        MarkdownInline::Image(ImagePolicy::RemoteChip {
            href,
            domain,
            alt,
            title,
        }) => {
            let i18n = use_i18n();
            link_view(
                SafeUrl::External { href, domain },
                title,
                view! { <span>{move || t!(i18n, channels.md_image)}{alt}</span> }.into_any(),
            )
        }
        MarkdownInline::Image(ImagePolicy::Blocked { alt, .. }) => {
            let i18n = use_i18n();
            view! { <span>{move || t!(i18n, channels.md_image_blocked)}{alt}</span> }.into_any()
        }
        MarkdownInline::LineBreak => view! { <br/> }.into_any(),
    }
}
fn highlighted_span_view(span: syntax::HighlightedSpan) -> AnyView {
    match span.class {
        "text-fg-muted" => view! { <span class="text-fg-muted">{span.text}</span> }.into_any(),
        "text-fg-secondary" => {
            view! { <span class="text-fg-secondary">{span.text}</span> }.into_any()
        }
        "text-success" => view! { <span class="text-success">{span.text}</span> }.into_any(),
        "text-info" => view! { <span class="text-info">{span.text}</span> }.into_any(),
        "text-caution" => view! { <span class="text-caution">{span.text}</span> }.into_any(),
        _ => view! { <span class="text-fg">{span.text}</span> }.into_any(),
    }
}
fn external_navigation_available() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        !crate::api::desktop_transport::is_tauri_host()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}
fn link_view(url: SafeUrl, title: Option<String>, content: AnyView) -> AnyView {
    match url {
        SafeUrl::External { href, domain } if external_navigation_available() => view! { <a href=href title=title target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">{content}<small class="ob-markdown-domain">{domain}</small></a> }.into_any(),
        SafeUrl::External { domain, .. } => view! { <span>{content}<small class="ob-markdown-domain">{domain}</small></span> }.into_any(),
        SafeUrl::Inert { .. } => view! { <span>{content}</span> }.into_any(),
    }
}

#[component]
fn CodeBlock(lang: String, code: String) -> impl IntoView {
    let spans = syntax::highlight_code(&code, &lang)
        .into_iter()
        .flatten()
        .map(highlighted_span_view)
        .collect_view();
    view! { <div class="ob-markdown-code"><div class="ob-skill-chips"><code>{if lang.is_empty() { "text".to_owned() } else { lang }}</code>
        <CopyButton text=code/>
    </div><pre><code>{spans}</code></pre></div> }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dangerous_links_and_unverified_attachments_are_inert() {
        for url in [
            "javascript:alert(1)",
            "\nhttps://example.test",
            "https://user:pass@example.test",
            "/api/private/file",
            "openbot-attachment://secret",
            "data:image/png,x",
        ] {
            assert!(
                matches!(SafeUrl::parse(url), SafeUrl::Inert { .. }),
                "{url}"
            );
        }
        assert!(matches!(
            ImagePolicy::classify("https://example.test/pixel", "alt", None),
            ImagePolicy::RemoteChip { .. }
        ));
    }
    #[test]
    fn streaming_matches_whole_document_at_every_utf8_boundary() {
        let documents = [
            "# 标题\n\n- one\n- **two**\n\n> quote\n\n```rust\nlet x = 1;\n```\n",
            "a\n\nb\n\nc\n\n[link][r]\n\n[r]: https://example.test\n",
            "| A | B |\n|:--|--:|\n| 一 | 二 |\n",
            "<script>boom()</script>\n\nA &amp; B\n",
        ];
        for document in documents {
            let mut cache = memo::StreamingMemoStore::new();
            for end in (0..=document.len()).filter(|i| document.is_char_boundary(*i)) {
                let actual = cache
                    .process_stream("test", &document[..end])
                    .into_iter()
                    .map(|entry| (*entry.block).clone())
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual,
                    parser::parse_markdown(&document[..end]),
                    "prefix {end}"
                );
            }
        }
    }
    #[test]
    fn cache_budget_eviction_and_append_reuse_do_not_cross_owners() {
        let mut cache = memo::StreamingMemoStore::new();
        for i in 0..40 {
            cache.process_stream(&format!("message-{i}"), "one\n\ntwo\n\nthree\n\nfour\n");
        }
        assert!(cache.message_count() <= memo::MAX_CACHE_MESSAGES);
        assert!(cache.retained_bytes() <= memo::MAX_CACHE_BYTES);
        let text = "one\n\ntwo\n\nthree\n\nfour\nextra";
        cache.process_stream("message-39", text);
        assert!(cache.last_parsed_bytes() < text.len());
        assert_eq!(memo::StreamingMemoStore::new().message_count(), 0);
        assert!(SafeUrl::parse("https://example.test").is_external());
    }
    #[test]
    fn oversized_and_deep_documents_have_bounded_plain_previews() {
        for document in ["中".repeat(50_000), format!("{}deep", "> ".repeat(80))] {
            assert!(matches!(
                parser::parse_markdown(&document).as_slice(),
                [MarkdownBlock::Limited { .. }]
            ));
        }
    }
    #[test]
    fn syntax_preserves_exact_multiline_code_and_all_declared_tokens_resolve() {
        for lang in [
            "bash",
            "sh",
            "powershell",
            "rust",
            "toml",
            "json",
            "yaml",
            "sql",
            "ts",
            "tsx",
            "js",
            "jsx",
            "html",
            "css",
            "md",
            "py",
            "go",
            "java",
            "kotlin",
            "swift",
            "c",
            "cpp",
            "diff",
            "dockerfile",
        ] {
            assert_ne!(syntax::resolve_syntax(lang).name, "Plain Text", "{lang}");
        }
        let code = "/* first\nstill comment */\nlet 中文 = 1;\n";
        assert_eq!(
            syntax::highlight_code(code, "rust")
                .into_iter()
                .flatten()
                .map(|span| span.text)
                .collect::<String>(),
            code
        );
        assert_eq!(syntax::resolve_syntax("unknown").name, "Plain Text");
    }
}

#[cfg(feature = "design-gallery")]
#[component]
pub(crate) fn MarkdownPreview() -> impl IntoView {
    let source = RwSignal::new("## 工作计划 · Plan\n\n这是 **重点**、*说明*、~~旧项~~和 `inline code`。\n\n3. 核对来源\n4. 交付结果\n\n- [x] 已完成\n- [ ] 待复核\n\n> 引用保持层级。\n\n| 模块 | 状态 |\n|:---|---:|\n| 技能 | 已接通 |\n| Screen | 待接通 |\n\n```rust\n// Evidence first\nfn main() {\n    let text = \"你好，Wrok Bot\";\n    println!(\"{}\", text);\n}\n```\n\n[参考来源](https://example.test/reference)\n\n![remote pixel](https://example.test/pixel.png)\n\n<script>alert('inert')</script>\n".to_owned());
    view! { <section class="ob-page" id="markdown-preview"><h1 class="ob-page-title">"Markdown preview"</h1><crate::primitives::Textarea value=source id="markdown-preview-source" aria_label="Markdown source"/>
        <StreamingMarkdownBody content=Signal::derive(move || source.get())/>
    </section> }
}
