# 007 First Light FOV/black bars/intro fixes

I love First Light. That said, there are a bunch of annoying things that grate
on me, like that you can't adjust the very tight FOV on ultrawide, the black
bars in cutscenes, and that you have to go through the super long warnings and
intro screens every time you start the game...

As such, here is a small set of fixes that bypass all the intro screens,
automatically starts the latest game, allows FOV adjustment, and removes all
black bars.

I tried to use reflection and working backwards from render pass metadata as
much as possible so hopefully this should keep working when the game is
updated.

By default we also skip intros and resume the latest save, if there is one.

# Compilation

Use `build.cmd`.

# Installation

Copy `dinput8.dll` next to `007FirstLight.exe`. `firstlightfixes.ini` is created
there on the first run.

# Screenshots

## Fixed

![](screenshots/fov-1.4.jpg)
![](screenshots/cutscene-no-bars.jpg)

## Default

![](screenshots/fov-stock.jpg)
![](screenshots/cutscene-bars.jpg)
