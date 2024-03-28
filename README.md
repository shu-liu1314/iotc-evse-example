# iotc-evse-example
iotconnect EVSE example

## Workspace build instructions
1. Clone the sources into a working directory of your choice
```bash
git clone git@github.com:pywtk/iotc-evse-example.git
```

2. Open up MCUXpresso IDE1.
3. When asked to open a workspace navigate to the nxpev1060mg dir.
4. Import the projects as follows:
   
![image](https://github.com/pywtk/iotc-evse-example/assets/131452865/73b926b7-4f2b-4587-a9a2-904d108806f3)

5. Select the nxpev1060mg dir within the cloned repo

![image](https://github.com/pywtk/iotc-evse-example/assets/131452865/65c97069-62a4-4684-87f6-6befbc167b12)

6. Check the pitcured projects, remember to untick the "Copy Projects into Workspace" option in order to do so.

![image](https://github.com/pywtk/iotc-evse-example/assets/131452865/de71926d-c474-4c04-a7d4-1893cbfb687b)

7. Build the evkmimxrt1060_netduo_lib_V2_duo project 1st by clicking build as pictured.

![image](https://github.com/pywtk/iotc-evse-example/assets/131452865/3c1ee460-70d4-4282-bdc4-2ee33d2e2996)

8. Build the RT1060_EasyEVSE_V2 project 2nd by clicking build as pictured.

![image](https://github.com/pywtk/iotc-evse-example/assets/131452865/4959c203-0c3d-482b-b9ff-fdde1259b400)

9. Both should build without error or code edits. Once finished & with the board connected via USB click Debug. You will probably see the next 2 prompts, just click OK.

![image](https://github.com/pywtk/iotc-evse-example/assets/131452865/7372ffbd-124d-42fa-b719-d4668ce5da1e)

![image](https://github.com/pywtk/iotc-evse-example/assets/131452865/4b629be8-c977-459a-a14a-b8484fbaca6e)

& that should be it!
