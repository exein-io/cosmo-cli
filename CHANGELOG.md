# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) with little changes to have more compacted lists,
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<hr>

## [0.5.0] - 2021-05-24

* CHANGED
    * Collapsed init and install into a single init
* ADDED
    * Get kernel version during init phase
    * Static policies as an optional feature
* REMOVED
    * cp_no_dereference wrapper (unused code)
* FIXED
    * error installing mle model
    * error mispelling tag/tags in cli param getter

## [0.4.0] - 2021-04-07

* ADDED
    * Model download command
    * Install command inplace
    * Yocto support
* CHANGED
    * Refactoring Api Server client
    * Refactoring Authentication System
    * Refactoring make module + make errors
    * Inplace Openwrt installation
    * Inplace Buildroot installation
    * No more little endian u16 in cli params
    * Openwrt and Buildroot sync package switched off
    * Switched notify of builds to the new installations idea
* REMOVED
    * Build command

## [0.3.0] - 2021-03-11

* ADDED
    * Receiver counter for received hooks
    * Make verbose for OpenWrt
    * Remote repository for kernel patches
    * Remote repository for Exein packages
    * CMake upgrade to 3.19.1 for OpenWrt (necessary to build Tensorflow 2.4)
    * Autotag
* CHANGED
    * Temporary disabled the wait and build feature 
* REMOVED
    * Custom toolchain in make commands (now should be passed via environment if necessary) 
    * Removed bundled Exein version

## [0.2.1] - 2021-02-09

* FIXED
    * Enable Exein in OpenWrt

<hr>

## Change types template

* ADDED 
* CHANGED
* DEPRECATED
* REMOVED
* FIXED
* SECURITY