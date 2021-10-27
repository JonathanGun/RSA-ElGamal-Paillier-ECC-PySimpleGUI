from datetime import datetime
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
            [sg.T("Method", size=(15, 1)), sg.DropDown(["RSA", "ElGamal", "Paillier", "ECC"], key="keygen_method", default_value="RSA", size=(10, 1))],
            [sg.T("Public Key", size=(15, 1)), sg.In(key="pubkey_gen", size=(55, 1))],
            [sg.T("Private Key", size=(15, 1)), sg.In(key="privkey_gen", size=(55, 1))],
            [sg.T("Public Key File", size=(15, 1)), sg.In(key="pubkey_filename", size=(55, 1))],
            [sg.T("Private Key File", size=(15, 1)), sg.In(key="privkey_filename", size=(55, 1))],
            [sg.Button("Generate Public/Private Key Pair", pad=(5, 10), key="generate")],
        ], key="keygen"),
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

            [sg.Button("Encrypt", pad=(5, 10), key="encrypt"), sg.T("vvv   ^^^"), sg.Button("Decrypt", pad=(5, 10), key="decrypt")],

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
            [sg.Button("Save Plaintext", pad=(5, 10), key="save_plaintext"), sg.Button("Save Ciphertext", pad=(5, 10), key="save_ciphertext")],
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


CIPHER_MAP = {
    "RSA": RSA,
    "ElGamal": ElGamal,
    "Paillier": Paillier,
    "ECC": ECC,
}
window = sg.Window(Config.APP_NAME, layout)

while sg_input := window.read():
    debug_text, debug_color = "", None
    print(sg_input)

    try:
        match sg_input:
            case ((sg.WIN_CLOSED | "Exit"), _):
                break
            case (("encrypt" | "decrypt") as event, values):
                method = values["method"]
                cipher = CIPHER_MAP.get(method)
                window["filename"].update(datetime.now().strftime("%Y%m%d-%H%M%S"))
                match (event, values):
                    case ("encrypt", {
                        "plaintext": plaintext,
                        "pubkey_text": pubkey,
                        "pubkey_file": pubkey_file,
                        "pubkey_source": pubkey_source,
                    }):
                        # Read pubkey
                        pubkey = pubkey if pubkey_source == "pubkey_text_tab" else load_file(pubkey_file)[0]
                        pubkey = int(pubkey)
                        plaintext = int(plaintext)
                        cipher = cipher(plaintext=plaintext, pubkey=pubkey)
                        cipher.encrypt()
                        window["ciphertext"].update(cipher.ciphertext)

                    case ("decrypt", {
                        "ciphertext": ciphertext,
                        "privkey_text": privkey,
                        "privkey_file": privkey_file,
                        "privkey_source": privkey_source,
                    }):
                        # Read privkey
                        privkey = privkey if privkey_source == "privkey_text_tab" else load_file(privkey_file)[0]
                        privkey = int(privkey)
                        ciphertext = int(ciphertext)
                        cipher = cipher(ciphertext=ciphertext, privkey=privkey)
                        cipher.decrypt()
                        window["plaintext"].update(cipher.plaintext)

                debug_text, debug_color = f"Succesfully {event}ed!", Config.SUCCESS_COLOR

            case ("generate", {"method": "RSA"}):
                pubkey_gen, privkey_gen = CIPHER_MAP.get(method).generate_key(seed=datetime.now())
                window["pubkey_gen"].update(pubkey_gen)
                window["privkey_gen"].update(privkey_gen)

            case (event, {"filename": filename}) if filename == "":
                debug_text, debug_color = "Output filename cannot be empty", Config.FAIL_COLOR
            case ("save_plaintext", {"filename": filename}):
                write_file("out/" + filename, cipher.plaintext)
            case ("save_ciphertext", {"filename": filename}):
                write_file("out/" + filename, cipher.ciphertext)

    except Exception as e:
        debug_text, debug_color = str(e), Config.FAIL_COLOR

    window["debug"].update(debug_text)
    window["debug"].update(background_color=debug_color)

window.close()
