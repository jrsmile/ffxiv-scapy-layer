import pyvjoy
import time
import PIL.ImageGrab
import math
import pyautogui
j = pyvjoy.VJoyDevice(1)
x = 1897
y = 917

def distance(c1, c2):
    (r1,g1,b1) = c1
    (r2,g2,b2) = c2
    return math.sqrt((r1 - r2)**2 + (g1 - g2) ** 2 + (b1 - b2) **2)

def bright():
    greyscale_image = PIL.ImageGrab.grab(bbox=(x-100,y-100,x+100,y+100)).convert('L')
    histogram = greyscale_image.histogram()
    pixels = sum(histogram)
    brightness = scale = len(histogram)
    for index in range(0, scale):
        ratio = histogram[index] / pixels
        brightness += ratio * (-scale + index)
    current_brightness = brightness / scale
    return current_brightness

while True:
    print("casting")
    j.set_axis(pyvjoy.HID_USAGE_SL1, 0x8000)
    time.sleep(0.1)
    j.set_button(1,1)
    time.sleep(1)
    j.set_button(1,0)
    time.sleep(0.1)
    j.set_axis(pyvjoy.HID_USAGE_SL1, 0x1)
    print("waiting for bite...")
    relative_brightness = bright()
    while abs(relative_brightness) - abs(bright()) <= 0.4 :
        print(f"current_brightness {bright()} relative_brightness {relative_brightness} difference {abs(relative_brightness) - abs(bright())}")
        relative_brightness = bright()
        time.sleep(0.1)

        
    print("got one")
    j.set_axis(pyvjoy.HID_USAGE_SL1, 0x8000)
    time.sleep(0.1)
    j.set_button(3,1)
    time.sleep(1)
    j.set_button(3,0)
    time.sleep(0.1)
    j.set_axis(pyvjoy.HID_USAGE_SL1, 0x1)
    time.sleep(2)
