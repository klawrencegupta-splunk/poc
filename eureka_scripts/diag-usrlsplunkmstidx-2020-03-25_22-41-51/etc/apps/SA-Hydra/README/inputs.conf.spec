*ALL STANZAS INTENTIONALLY COMMENTED TO AVOID CONFUSION IN GUI

*[example_hydra_worker://<name>]
*capabilities = <value>
* this is the comma delimited list of actions that the worker can perform (job types)
*log_level = <value>
* the level at which the worker will log data.
* duration = <value>
* the minimum time between runs of the input should it exit for some reason

*[example_hydra_scheduler://<name>]
* the scheduler should only exist once
*log_level = <value>
* the level at which the scheduler will log data.
* duration = <value>
* the minimum time between runs of the input should it exit for some reason