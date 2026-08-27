#!/usr/bin/env bash
count=$(ls /nonexistent 2>&1)
echo "$count"
