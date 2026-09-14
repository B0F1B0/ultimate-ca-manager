/**
 * Element styling for ReactMarkdown output - shared by every markdown surface
 * (release notes, ACME ToS preview) so they render consistently. Container
 * concerns (padding, background, max-height, text size) stay with the caller.
 */
export const MARKDOWN_ELEMENT_CLASSES = "[&_h1]:text-base [&_h1]:font-semibold [&_h1]:text-text-primary [&_h1]:mt-3 [&_h1]:mb-1 [&_h2]:text-sm [&_h2]:font-semibold [&_h2]:text-text-primary [&_h2]:mt-3 [&_h2]:mb-1 [&_h3]:text-xs [&_h3]:font-semibold [&_h3]:text-text-primary [&_h3]:mt-2 [&_h3]:mb-1 [&_ul]:list-disc [&_ul]:pl-4 [&_ul]:my-1 [&_ol]:list-decimal [&_ol]:pl-4 [&_ol]:my-1 [&_li]:my-0.5 [&_li]:text-text-secondary [&_strong]:text-text-primary [&_strong]:font-semibold [&_code]:text-accent-primary [&_code]:bg-bg-tertiary [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-xs [&_p]:my-1 [&_a]:text-accent-primary [&_a]:underline [&_hr]:border-border [&_hr]:my-2"
