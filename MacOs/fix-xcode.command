#!/bin/bash

base_dir=$(dirname "$0")
cd "$base_dir"

echo -e "\033[1;35m *** Deleting Derived Data *** \033[0m"
rm -rf ~/Library/Developer/Xcode/DerivedData/*

echo -e "\033[1;35m *** Deleting xCode Cache *** \033[0m"
rm -rf ~/Library/Caches/com.apple.dt.Xcode

echo
echo -e "\033[1;32m *** Rescue Success! *** \033[0m"
echo -e "\033[1;32m *** Restart your Xcode *** \033[0m"


