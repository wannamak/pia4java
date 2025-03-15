# Private Internet Access for Java

## About

Java implementation of shell scripts to connect to the
Private Internet Access VPN.

The tool must be run with <code>sudo</code> (requirement of wg).

Currently, it only routes the particular domain specified in the
configuration, rather than all domains.

## Usage

<code>cp props/sample-config.txt props/config.txt</code> and edit.

<code>ant</code>

<code>./run.sh up</code>

<code>./run.sh down</code>
