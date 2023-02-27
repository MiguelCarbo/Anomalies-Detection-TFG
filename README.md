# Anomalies-Detection-TFG
Miguel Ivars Carbo's TFG 

On a first approach to this work, basic Isolation Forest techniques are going to be tested on the CIC-IDS 2017 Dataset.

For that purpose, two Google Colab Notebooks are being used. The one using the ScickitLearn Isolation Forest Library may be susceptible to be dropped because of its high computational requirements. Therefore, the PYOD library, which also contains other algorithms may be preferably used.

After having set a solid basis from which to work, the analysis shall be extended specifically to the TLS domain. Most of today's C2 connections use TLS which is why the analysis of this field is regarded as being of interest.

The .log files that are analysed are extracted using Zeek, a simple tool that can offer a fast and effective way to process big amounts of connections.

*Note that the project is still under development and further improvement are still to be made*
