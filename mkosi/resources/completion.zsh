#compdef mkosi
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=zsh

_mkosi_verb(){
    if (( CURRENT == 1 )); then
        _describe -t commands 'mkosi verb' _mkosi_verbs
    else
        local curcontext="$curcontext"
        cmd="${${_mkosi_verbs[(r)$words[1]:*]%%:*}}"
        if (( $#cmd )); then
            if (( $+functions[_mkosi_$cmd] )); then
                _mkosi_$cmd
            else
                _message "no more options"
            fi
        else
            _message "unknown mkosi verb: $words[1]"
        fi
    fi
}
