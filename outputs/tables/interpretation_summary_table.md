| Experiment | Delivery-side observation | Usefulness-side observation | Interpretation |
| --- | --- | --- | --- |
| Baseline | Delivery remains complete. | Most delivered events are useful. | Healthy telemetry-to-belief coupling. |
| Delay | Delivery remains complete. | Stale-event fraction increases. | Events can arrive but no longer support timely belief maintenance. |
| Loss | Delivery decreases. | Useful fraction remains high among delivered events. | Lower volume is not automatically lower usefulness density. |
| Noise | Delivery remains high. | Misleading events and belief error increase. | Corrupted telemetry can weaken defender belief despite delivery. |
| Suppression | Delivery decreases. | Belief entropy increases. | Missing high-value evidence degrades defender certainty. |
| Alert flood | Delivery volume inflates. | Useful-event fraction collapses. | More telemetry can produce less useful evidence per event. |
