# Simple Shortest Path First (SPF) Controller in Ryu (for Mininet)

## Synopsis
This is an implementation of the shortest path first (SPF) controller module in Ryu for Mininet.

## Requirements
To use the controller, Ryu and networkx are essential. Install them by
  ```
  pip install ryu
  pip install networkx
  ```

## Usage
  Run the controller by
  ``ryu-manager ryu_spf_controller.py --observe-links``

  Or in the Python script for Mininet, do
  ```
  net.addController(
    name='c0',
    controller=Controller,
    command='ryu-manager',
    cargs='--ofp-tcp-listen-port %s --observe-links ryu_spf_controller.py'
  )
  ```