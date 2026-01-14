![Logo](images/nemesis-dark.png#only-dark)
![Logo](images/nemesis-light.png#only-light)

<p align="center">
<img src="https://img.shields.io/badge/version-2.0.0-blue" alt="version 2.0.0"/>
<a href="https://join.slack.com/t/bloodhoundhq/shared_invite/zt-1tgq6ojd2-ixpx5nz9Wjtbhc3i8AVAWw">
    <img src="https://img.shields.io/badge/Slack-%23nemesis—chat-blueviolet?logo=slack" alt="Slack"/>
</a>
<a href="https://twitter.com/tifkin_">
    <img src="https://img.shields.io/twitter/follow/tifkin_?style=social"
      alt="@tifkin_ on Twitter"/></a>
<a href="https://twitter.com/harmj0y">
    <img src="https://img.shields.io/twitter/follow/harmj0y?style=social"
      alt="@harmj0y on Twitter"/></a>
<a href="https://twitter.com/0xdab0">
    <img src="https://img.shields.io/twitter/follow/0xdab0?style=social"
      alt="@0xdab0 on Twitter"/></a>
<a href="https://github.com/specterops#nemesis">
    <img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json&style=flat"
      alt="Sponsored by SpecterOps"/>
</a>
</p>
<hr />

## Overview

Nemesis is an open-source, centralized data processing platform that ingests, enriches, and allows collaborative analysis (with humans and AI) of files collected during offensive security assessments.

Nemesis 2.0 is built on [Docker](https://www.docker.com/) with heavy [Dapr integration](https://dapr.io/), our goal with Nemesis was to create a centralized file processing platform that functions as an "offensive VirusTotal".

_Note: the previous Nemesis 1.0.1 code base has been preserved [as a branch](https://github.com/SpecterOps/Nemesis/tree/nemesis-1.0.1)_

## Setup / Installation
Follow the [quickstart guide](quickstart.md).


## Usage
See the [Nemesis Usage Guide](usage_guide.md).


## Additional Information

Blog Posts

| Title                                                                                                                                                            | Nemesis Version | Date         |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------------ |
| [*Nemesis 2.0*](https://specterops.io/blog/2025/08/05/nemesis-2-0/)                                                                                              | v2.0            | Aug 5, 2025  |
| [*Nemesis 1.0.0*](https://posts.specterops.io/nemesis-1-0-0-8c6b745dc7c5)                                                                                        | v1.0            | Apr 25, 2024 |
| [*Summoning RAGnarok With Your Nemesis*](https://posts.specterops.io/summoning-ragnarok-with-your-nemesis-7c4f0577c93b)                                          | v1.0            | Mar 13, 2024 |
| [*Shadow Wizard Registry Gang: Structured Registry Querying*](https://posts.specterops.io/shadow-wizard-registry-gang-structured-registry-querying-9a2fab62a26f) | v1.0            | Sep 5, 2023  |
| [*Hacking With Your Nemesis*](https://posts.specterops.io/hacking-with-your-nemesis-7861f75fcab4)                                                                | v1.0            | Aug 9, 2023  |
| [*Challenges In Post-Exploitation Workflows*](https://posts.specterops.io/challenges-in-post-exploitation-workflows-2b3469810fe9)                                | v1.0            | Aug 2, 2023  |
| [*On (Structured) Data*](https://posts.specterops.io/on-structured-data-707b7d9876c6)                                                                            | v1.0            | Jul 26, 2023 |


Presentations:

| Title                                                                      | Date         |
|----------------------------------------------------------------------------|--------------|
| OffensiveX 2025                                                            | Jun 19, 2025 |
| [*x33fcon 2025*](https://www.youtube.com/watch?v=RjLqfhQGUnE)              | Jun 13, 2025 |
| [*SAINTCON 2023*](https://www.youtube.com/watch?v=0q9u2hDcpIo)             | Oct 24, 2023 |
| [*BSidesAugusta 2023*](https://www.youtube.com/watch?v=Ug9r7lCF_FA)        | Oct 7, 2023  |
| [*44CON 2023*](https://www.youtube.com/watch?v=tjPTLBGI7K8)                | Sep 15, 2023 |
| [*BlackHat Arsenal USA 2023*](https://www.youtube.com/watch?v=Ms3o8n6aS0c) | Sep 15, 2023 |


## Acknowledgments

Nemesis is built on large chunk of other people's work. Throughout the codebase we've provided citations, references, and applicable licenses for anything used or adapted from public sources. If we're forgotten proper credit anywhere, please let us know or submit a pull request!

We also want to acknowledge Evan McBroom, Hope Walker, and Carlo Alcantara from [SpecterOps](https://specterops.io/) for their help with the initial Nemesis concept and amazing feedback throughout the development process. Also thanks to [Matt Ehrnschwender](https://twitter.com/M_alphaaa) for tons of k3s and GitHub workflow help in Nemesis 1.0!

And finally, shout out to OpenAI and Claude for helping with this rewrite.