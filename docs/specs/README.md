This directory contains the files that define the Longfellow ZK spec.

## Setup
You will need the mmark and xml2rfc programs to work on this spec.
On mac, you can use `brew install mmark xml2rfc idnits`.

## Producing html
Running `make` produces the xml, text and html rendering.

## Updating the website
The goal is to create a github workflow that recreates the html and copies it into the proper directory to be served from gh-pages.

## Issues
We intend to use the built-in issues system to manage edits and updates to this specification.