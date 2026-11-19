/**
 * Git Bash client half.
 *
 * This is not an ES module: DSH's client loader evaluates the emitted file and
 * calls the factory with the modules the plugin declares in
 * `dsh.client.inject`. Nothing is required directly — the whole feature is a
 * stylesheet keyed off the shipped row's own markup, so there is no React
 * component to mount and no slot election to win.
 *
 * Scope note: this half only makes long commands readable. It never touches the
 * executor, so a failure here costs presentation, not shell behaviour.
 *
 * @module dsh-plugin-git-bash-rs/client
 */
export {};
