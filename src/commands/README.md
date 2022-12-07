# Control Plane Commands

This directory contains the commands that will be uploaded to each of the P4 switches.
The commands will be executed by "simple_switch_CLI", the control plane for BMv2.
While some example commands have been included in this directory, the main Jupyter notebook is able to automatically generate these commands in the specified configuration ("both_paths", "slow_path", or "fast_path"). This is because the commands contain the MAC addresses of the various interfaces of the nodes, which change whenever a new slice is created.
