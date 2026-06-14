"""Experiment 2: Impairment sweep.

Runs baseline, delay, loss, noise, adversarial suppression, and alert flood
conditions under a shared synthetic scenario.
"""

from astra.experiments import run_sweep

if __name__ == "__main__":
    run_sweep(
        config_paths=[
            "configs/synthetic_baseline.yaml",
            "configs/impairment_delay.yaml",
            "configs/impairment_loss.yaml",
            "configs/impairment_noise.yaml",
            "configs/impairment_adversarial_suppression.yaml",
            "configs/impairment_alert_flood.yaml",
        ]
    )
