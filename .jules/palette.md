## 2026-05-11 - Pagination Accessibility
**Learning:** Pagination controls built with Go templates were missing semantic HTML and ARIA labels.
**Action:** Always wrap pagination in a `<nav aria-label="Pagination">`, add `aria-label` to directional links, and use `aria-current="page"` on the active page indicator.
