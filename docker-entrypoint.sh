#!/usr/bin/env bash

exec python -u /app/youtrackutils/redmine2youtrack.py -m /app/mapping.json -l -M -w "$@"
