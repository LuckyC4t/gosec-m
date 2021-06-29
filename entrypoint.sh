#!/usr/bin/env bash

# Expand the arguments into an array of strings. This is requires because the GitHub action
# provides all arguments concatenated as a single string.
ARGS=("$@")

# update rules
echo 'update rules'
git -C /gosec-m pull

/bin/gosec-m -rule=/gosec-m/dynamicRules ${ARGS[*]}