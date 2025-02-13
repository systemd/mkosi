# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash

_mkosi_compgen_files() {
    compgen -f -- "$1"
}

_mkosi_compgen_dirs() {
    compgen -d -- "$1"
}

_mkosi_completion() {
    local -a _mkosi_options
    local -A _mkosi_choices _mkosi_compgen _mkosi_verbs
    local -i curword_idx verb_seen

##VARIABLEDEFINITIONS##

    # completing_program="$1"
    local completing_word="$2"
    local completing_word_preceding="$3"

    if [[ "$completing_word" =~ ^- ]]  # completing an option
    then
        readarray -t COMPREPLY < <(compgen -W "${_mkosi_options[*]}" -- "${completing_word}")
        return
    elif [[ "$completing_word_preceding" =~ ^- ]]  # the previous word was an option
    then
        current_option="${completing_word_preceding}"
        current_option_choices="${_mkosi_choices[${current_option}]}"
        current_option_compgen="${_mkosi_compgen[${current_option}]}"

        # compgen options if we have them
        if [[ -n "${current_option_compgen}" ]]
        then
            readarray -t COMPREPLY < <("${current_option_compgen}" "${completing_word}")
            return
        fi

        # add choices if the current option has them
        readarray -t COMPREPLY -O "${#COMPREPLY[@]}" \
                  < <(compgen -W "${current_option_choices}" -- "${completing_word}")

        # if this (maybe) takes arguments, we'll just fall back to files
        readarray -t COMPREPLY -O "${#COMPREPLY[@]}" \
                    < <(_mkosi_compgen_files "${completing_word}")
    fi

    # the preceding word wasn't an option or one that doesn't take arguments,
    # let's get creative and check the whole argument list so far
    while ((curword_idx < COMP_CWORD))
    do
        # check if we've seen a verb already, then we just try files
        if [[ -n "${_mkosi_verbs[${COMP_WORDS[${curword_idx}]}]}" ]]
        then
            verb_seen=$curword_idx
            break
        fi
        curword_idx=$((curword_idx + 1))
    done
    if ((verb_seen))
    then
        readarray -t COMPREPLY < <(_mkosi_compgen_files "${completing_word}")
    else
        readarray -t COMPREPLY < <(compgen -W "${_mkosi_verbs[*]}" -- "${completing_word}")
    fi
}

complete -o filenames -F _mkosi_completion mkosi
complete -o filenames -F _mkosi_completion python -m mkosi
