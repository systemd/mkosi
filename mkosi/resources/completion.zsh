#compdef mkosi
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=zsh

_mkosi_verb(){
    if (( CURRENT == 1 )); then
        _describe -t commands 'mkosi verb' _mkosi_verbs
    else
        local curcontext="$curcontext"
        if [[ "$curcontext" == ':complete:mkosi:argument-rest' ]]; then
            _files
        fi
    fi
}
