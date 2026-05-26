# doxygen-awesome-css (vendored)

Modern HTML/CSS theme for Doxygen's generated documentation by
[jothepro](https://github.com/jothepro/doxygen-awesome-css). Vendored
here so the docs build doesn't need an extra fetch step in CI.

## Source and licence

Pinned to release **v2.4.2** of
https://github.com/jothepro/doxygen-awesome-css. The upstream LICENSE
(MIT) is preserved in this directory alongside the CSS.

## Refreshing

To bump to a newer release, replace `doxygen-awesome.css` and
`LICENSE` with the files of the same name at the chosen tag (e.g.
https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v2.5.0/doxygen-awesome.css),
update the pin reference in this README, then re-run
`doxygen docs/Doxyfile` and eyeball the output for regressions.
