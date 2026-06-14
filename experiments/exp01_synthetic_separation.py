"""Experiment 1: Alert delivery versus alert usefulness.

Goal:
Show that delivered alert volume and useful defender knowledge can separate
under telemetry impairment.
"""

from astra.experiments import main

if __name__ == "__main__":
    main(config_path="configs/synthetic_baseline.yaml")
