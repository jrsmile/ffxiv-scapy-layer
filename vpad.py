import vgamepad as vg
import time

gamepad = vg.VDS4Gamepad()

def attack(button, gamepad):
    gamepad.press_button(button=vg.DS4_BUTTONS.DS4_BUTTON_TRIGGER_RIGHT)
    gamepad.press_button(button)
    gamepad.update()
    time.sleep(0.5)
    gamepad.release_button(button)
    gamepad.release_button(button=vg.DS4_BUTTONS.DS4_BUTTON_TRIGGER_RIGHT)
    gamepad.update()
    time.sleep(0.5)

gamepad.reset()
gamepad.update()
# press a button to wake the device up
gamepad.press_button(button=vg.DS4_BUTTONS.DS4_BUTTON_TRIANGLE)
gamepad.update()
time.sleep(0.25)
gamepad.release_button(button=vg.DS4_BUTTONS.DS4_BUTTON_TRIANGLE)
gamepad.update()
time.sleep(0.25)

print ("switch controller in game")
time.sleep(20)

while True:
    print("cast")
    attack(vg.DS4_BUTTONS.DS4_BUTTON_CROSS,gamepad)
    print("waiting...")
    time.sleep(13)
    print("got one")
    attack(vg.DS4_BUTTONS.DS4_BUTTON_SQUARE,gamepad)
    time.sleep(7.0)