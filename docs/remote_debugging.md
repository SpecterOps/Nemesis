
## Remote Debugging

If you want to configure remote debugging for Nemesis, where you have a Visual Studio running on a host that's not the Nemesis host:

- Install the [remote-ssh](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh) extension on the Visual Studio host
- Add host the Nemesis host/VM and connect to it
- Open the Nemesis folder on the remote host
- On the terminal in Visual Studio (that's thus running on the remote Nemesis host) run `curl https://sdk.cloud.google.com | bash`
- from Preferences, select Open Remote Settings (JSON) (SSH \<HOST\>) and add the following:
```
{
    "http.proxySupport": "off"
}
```