from datetime import datetime
import os
from typing import List
import PySimpleGUI as sg

from ciphers.rsa import RSA
from ciphers.elgamal import ElGamal
from ciphers.paillier import Paillier
from ciphers.ecc import ECC


class Config:
    APP_NAME = "Tucil 4 Kriptografi"
    SUCCESS_COLOR = "#90EE90"
    FAIL_COLOR = "#d9534f"
    ABOUT = """
Created by:
- Michelle Theresia / 13518050
- Jonathan Yudi Gunawan / 13518084
"""


sg.theme("Reddit")
layout = [
    [sg.T(Config.APP_NAME, font="Any 20")],
    [sg.T("", key="debug")],
    [sg.TabGroup([[
        sg.Tab("Encrypt/Decrypt", [
            [sg.T("Method", size=(10, 1)), sg.DropDown(["RSA", "ElGamal", "Paillier", "ECC"], key="method", default_value="RSA", size=(10, 1))],
            [sg.T("Public Key:")],
            [sg.TabGroup([[
                sg.Tab("From Text", [
                    [sg.Multiline(key="pubkey_text", size=(70, 3))]
                ], key="pubkey_text_tab"),
                sg.Tab("From File", [
                    [sg.T("Select File", size=(10, 1)), sg.FileBrowse("Choose a file", key="pubkey_file", target=(sg.ThisRow, 2)), sg.T("", size=(40, 2))],
                ], key="pubkey_file_tab"),
            ]], key="pubkey_source")],
            [sg.Multiline(key="plaintext", size=(70, 10))],

            [sg.Button("Encrypt", pad=(5, 10)), sg.T("vvv   ^^^"), sg.Button("Decrypt", pad=(5, 10))],

            [sg.T("Private Key:")],
            [sg.TabGroup([[
                sg.Tab("From Text", [
                    [sg.Multiline(key="privkey_text", size=(70, 3))]
                ], key="privkey_text_tab"),
                sg.Tab("From File", [
                    [sg.T("Select File", size=(10, 1)), sg.FileBrowse("Choose a file", key="privkey_file", target=(sg.ThisRow, 2)), sg.T("", size=(40, 2))],
                ], key="privkey_file_tab"),
            ]], key="privkey_source")],
            [sg.Multiline(key="ciphertext", size=(70, 10))],

            [sg.T("Output File", size=(10, 1)), sg.In(key="filename", size=(60, 1))],
            [sg.Button("Save Plaintext", pad=(5, 10)), sg.Button("Save Ciphertext", pad=(5, 10))],
        ], key="encrypt_decrypt"),
        sg.Tab("About", [[sg.T(txt)] for txt in Config.ABOUT.strip().split("\n")], key="about"),
    ]], key="current_tab")],
]


def load_file(filepath: str) -> List[str]:
    # return list of string, 1 line = 1 element
    ret = []
    with open(filepath, "r") as f:
        ret += f.readlines()
    return ret


def write_file(filepath: str, content: List[str]) -> bool:
    with open(filepath, "w") as f:
        f.writelines(content)


window = sg.Window(Config.APP_NAME, layout)
event, values = window.read()


stego_object = None
while event not in (sg.WIN_CLOSED, "Exit"):
    event = event.lower()
    debug_text, debug_color = "", None
    print(event, values)

    if event in ["encrypt", "decrypt"]:
        ciphertext, plaintext, pubkey, privkey = "", "", 0, 0
        print("Method:", values["method"])

        if event == "encrypt":
            plaintext = values["plaintext"]

            # Read pubkey
            pubkey = values["pubkey_text"]
            window["filename"].update(datetime.now().strftime("%Y%m%d-%H%M%S") + "." + event[:3])
            if values["pubkey_source"] == "pubkey_file_tab":
                pubkey = load_file(values["pubkey_file"])[0]
                window["filename"].update(os.path.basename(values["pubkey_file"]) + "." + event[:3])

            # Try convert pubkey to int
            try:
                pubkey = int(pubkey)
            except Exception as e:
                debug_text, debug_color = str(e), Config.FAIL_COLOR

        elif event == "decrypt":
            ciphertext = values["ciphertext"]

            # Read privkey
            privkey = values["privkey_text"]
            window["filename"].update(datetime.now().strftime("%Y%m%d-%H%M%S") + "." + event[:3])
            if values["privkey_source"] == "privkey_file_tab":
                privkey = load_file(values["privkey_file"])[0]
                window["filename"].update(os.path.basename(values["privkey_file"]) + "." + event[:3])

            # Try convert privkey to int
            try:
                privkey = int(privkey)
            except Exception as e:
                debug_text, debug_color = str(e), Config.FAIL_COLOR

        if debug_color != Config.FAIL_COLOR:
            # Process (decrypt / encrypt)
            method = values["method"]
            cipher = RSA if method == "RSA" else ElGamal if method == "ElGamal" else Paillier if method == "Paillier" else ECC
            cipher = cipher(
                plaintext=plaintext,
                ciphertext=ciphertext,
                privkey=privkey,
                pubkey=pubkey,
            )
            getattr(cipher, event)()
            debug_text, debug_color = f"Succesfully {event}ed!", Config.SUCCESS_COLOR

    elif event.startswith("save"):
        filename = "out/" + values["filename"]
        if values["filename"]:
            try:
                write_file(filename, getattr(cipher, event.split()[-1]))
                debug_text, debug_color = f"Succesfully saved as {filename}", Config.SUCCESS_COLOR
            except Exception as e:
                print(e)
                debug_text, debug_color = f"Failed to save as {filename}", Config.FAIL_COLOR
        else:
            debug_text, debug_color = "Output filename cannot be empty", Config.FAIL_COLOR

    # Output
    if event in ["decrypt", "encrypt"] and debug_color == Config.SUCCESS_COLOR:
        window["ciphertext"].update(cipher.ciphertext)
        window["plaintext"].update(cipher.plaintext)
    window["debug"].update(debug_text)
    window["debug"].update(background_color=debug_color)

    # Get next value
    event, values = window.read()

window.close()
