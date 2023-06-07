# Datasets

There are 7 datasets we have open sourced and provided. You can see the instructions below on how to access and use the datasets below

| Name | VA | # Classes | Type of Data |
|------|----|-----------|-----------------|
|***simple_100_alexa***|Alexa|100|simple commands|
|***skills_100_alexa***|Alexa|100|skills|
|***stream_15_alexa***|Alexa|15|streaming commands|
|***simple_50_alexa***|Alexa|50|simple commands|
|***simple_50_google***|Google|50|simple commands|
|***simple_50_siri***|Siri|50|simple commands|
|***mix_100_alexa***|Alexa|100|simple commands, skills and streaming with background noise

## How to access the datasets

The datasets are available at this link: [https://privacy-datahub.csc.ncsu.edu/vafingerprinting]([https://](https://privacy-datahub.csc.ncsu.edu/vafingerprinting)). You can simply open the webpage in a browser and download them 

## How to setup the datasets

This setup is for all datasets excluding the split we used for *mix_100_alexa*

After you have downloaded the zipped dataset(s) you can then place them inside the `data` directory. Following command can be used with paths replaced

```
$ cp path/to/{dataset}.zip path/to/va-fingerprinting/data/
```

You can then extract the files by using the `unzip` command.

```
$ cd path/to/va-fingerprinting/data
$ unzip {dataset}.zip
```

If you get an error saying command not found you would need to install `unzip` utility

Finally, you can verify the required files are present by using `ls`

```console
$ ls {dataset}
captures    invoke_records
```

There should be two subdirectories present in the `{dataset}` directory namely `captures`, which contains the PCAP files and `invoke_records`, which contains the JSON files marking the ground truth and timestamp of each invocation made by our data collection process

To setup *mix_100_alexa* (based on temporal split) follow the instructions below:

- Setup the *mix_100_alexa* dataset as described above
- Download the invoke_records for the splits by downloading the following files `mix_100_alexa_train_ir.zip` and `mix_100_alexa_test_ir.zip`
- Copy the files in `data` directory and extract them one after the other by using the following command
```sh
unzip mix_100_alexa_{split}_ir.zip -d mix_100_alexa_{split}`
```
- (Option 1) Copy the `captures` directory from the `mix_100_alexa` folder to each of the `mix_100_alexa_{split}` folders by using the following.
```sh
cp -r mix_100_alexa/captures mix_100_alexa_{split}/
```
- (Option 2) If you encounter space problems you can also create a symbolic link instead of copying files in the previous step by using the command from inside the `mix_100_alexa{split}` directory
```
ln -s ../mix_100_alexa/captures captures
```