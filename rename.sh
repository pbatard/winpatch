#!/bin/bash

type -P sed &>/dev/null || { echo "sed command not found. Aborting." >&2; exit 1; }
type -P git &>/dev/null || { echo "git command not found. Aborting." >&2; exit 1; }

if [ ! -n "$1" ]; then
  echo "You must provide the new project name (eg. 'my-project')"
  exit 1
else
  NEW=$1
fi

if [[ $new =~ "_" ]]; then
   echo "A project names with underscore(s) is not suitable for AppVeyor"
   exit 1
fi

ORG=$(ls *.sln)
ORG="${ORG%.*}"
echo "Renaming '$ORG' to '$NEW'..."

sed -b -i "s/$ORG/$NEW/g" $ORG.sln README.md .vs/*.vcxproj* src/*.c
git mv $ORG.sln $NEW.sln
git mv .vs/$ORG.vcxproj .vs/$NEW.vcxproj
git mv .vs/$ORG.vcxproj.filters .vs/$NEW.vcxproj.filters
git mv .vs/$ORG.vcxproj.user .vs/$NEW.vcxproj.user
git mv src/$ORG.c src/$NEW.c

echo "Do not forget to change FRIENDLY_NAME in AppVeyor.yml and update README.md."
