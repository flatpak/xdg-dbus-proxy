xdg-dbus-proxy release checklist
================================

* Update NEWS, including release date
* Update version number in `meson.build`
* Commit the changes
* `meson dist`
* Do any final smoke-testing, e.g. update a package, install and test it
* `git evtag sign $VERSION`
* `git push --atomic origin main $VERSION`
* https://github.com/flatpak/xdg-dbus-proxy/releases/new
    * Fill in the new version's tag in the "Tag version" box
    * Title: `Release $VERSION`
    * Copy the `NEWS` text into the description
    * Upload the tarball that you built with `meson dist`
    * Get the `sha256sum` of the tarball and append it to the description
    * `Publish release`
