# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash

_mkosi_compgen_files() {
    compgen -f -- "$1"
}

_mkosi_compgen_dirs() {
    compgen -d -- "$1"
}

_mkosi_completion() {
    # completing_program="$1"
    local completing_word="$2"
    local completing_word_preceding="$3"

    if [[ "$completing_word" =~ ^- ]]  # completing an option
    then
        readarray -t COMPREPLY < <(compgen -W "${_mkosi_options[*]}" -- "${completing_word}")

    elif [[ "$completing_word_preceding" =~ ^- ]]  # the previous word was an option
    then
        current_option="${completing_word_preceding}"
        current_option_nargs="${_mkosi_nargs[${current_option}]}"
        current_option_choices="${_mkosi_choices[${current_option}]}"
        current_option_compgen="${_mkosi_compgen[${current_option}]}"

        if [[ -n "${current_option_compgen}" ]]
        then
            readarray -t COMPREPLY < <("${current_option_compgen}" "${completing_word}")
        fi
        readarray -t COMPREPLY -O "${#COMPREPLY[@]}" \
                  < <(compgen -W "${current_option_choices}" -- "${completing_word}")

        if [[ "${current_option_nargs}" == "?" ]]
        then
            readarray -t COMPREPLY -O "${#COMPREPLY[@]}" \
                      < <(compgen -W "${_mkosi_verbs[*]}" -- "${completing_word}")
        fi
    else
        # the preceding word wasn't an option, so we are doing position
        # arguments now and all of them are verbs
        readarray -t COMPREPLY < <(compgen -W "${_mkosi_verbs[*]}" -- "${completing_word}")
    fi
}

complete -o filenames -F _mkosi_completion mkosi
complete -o filenames -F _mkosi_completion python -m mkosi
