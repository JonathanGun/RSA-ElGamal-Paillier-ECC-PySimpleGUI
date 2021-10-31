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
        sg.Tab("Key Generation", [
            [sg.T("Choose Method")],
            [sg.TabGroup([[
                sg.Tab("RSA", [
                    # TODO chel
                    [sg.T("butuh input apa, masukin sini chel")],
                ], key="RSA_"),
                sg.Tab("ElGamal", [
                    # TODO chel
                ], key="ElGamal_"),
                sg.Tab("ECC", [
                    [sg.T("y=x^3+a*x+b (mod p)")],
                    [sg.T("a (int)", size=(10, 1)), sg.In(key="keygen_ecc_a", size=(60, 1))],
                    [sg.T("b (int)", size=(10, 1)), sg.In(key="keygen_ecc_b", size=(60, 1))],
                    [sg.T("p (int)", size=(10, 1)), sg.In(key="keygen_ecc_p", size=(60, 1))],
                    [sg.T("B (int, Base point seed)", size=(25, 1)), sg.In(key="keygen_ecc_base", size=(43, 1))],
                ], key="ECC_"),
                sg.Tab("Paillier", [
                    [sg.T("p (int)", size=(10, 1)), sg.In(key="keygen_paillier_p", size=(60, 1))],
                    [sg.T("q (int)", size=(10, 1)), sg.In(key="keygen_paillier_q", size=(60, 1))],
                    [sg.T("g (int)", size=(10, 1)), sg.In(key="keygen_paillier_g", size=(60, 1))],
                ], key="Paillier_"),
            ]], key="keygen_method")],
            [sg.Button("Generate Public/Private Key Pair", pad=(5, 10), key="generate")],
            [sg.HSep()],
            [sg.T("Public Key", size=(15, 1)), sg.In(key="pubkey_gen", size=(45, 1)), sg.T(".pub")],
            [sg.T("Private Key", size=(15, 1)), sg.In(key="privkey_gen", size=(45, 1)), sg.T(".pri")],
            [sg.T("Key Pair Filename", size=(15, 1)), sg.In(key="keygen_filename", size=(55, 1))],
            [sg.Button("Save Key Pair", pad=(5, 10), key="save_keygen")],
        ], key="keygen"),
        sg.Tab("Encrypt/Decrypt", [
            [sg.T("Choose Method")],
            [sg.TabGroup([[
                sg.Tab("RSA", [
                    # TODO chel
                    [sg.T("butuh input apa, masukin sini chel")],
                ], key="RSA"),
                sg.Tab("ElGamal", [
                    # TODO chel
                ], key="ElGamal"),
                sg.Tab("ECC", [
                    [sg.T("y=x^3+a*x+b (mod p)")],
                    [sg.T("a (int)", size=(10, 1)), sg.In(key="ecc_a", size=(60, 1))],
                    [sg.T("b (int)", size=(10, 1)), sg.In(key="ecc_b", size=(60, 1))],
                    [sg.T("p (int)", size=(10, 1)), sg.In(key="ecc_p", size=(60, 1))],
                    [sg.T("B (int, Base point seed)", size=(25, 1)), sg.In(key="ecc_base", size=(40, 1))],
                ], key="ECC"),
                sg.Tab("Paillier", [
                    [sg.T("No input. Go on")],
                ], key="Paillier"),
            ]], key="method")],
            [sg.Button("Validate Input", pad=(5, 10), key="validate")],
            [sg.HSep()],

            [sg.T("Public Key", size=(10, 1)), sg.TabGroup([[
                sg.Tab("From Text", [
                    [sg.In(key="pubkey_text", size=(55, 1))]
                ], key="pubkey_text_tab"),
                sg.Tab("From File", [
                    [sg.T("Select File", size=(10, 1)), sg.FileBrowse("Choose a file", key="pubkey_file", target=(sg.ThisRow, 2)), sg.T("", size=(30, 2))],
                ], key="pubkey_file_tab"),
            ]], key="pubkey_source")],
            [sg.T("Plaintext", size=(10, 1)), sg.In(key="plaintext", size=(60, 1))],

            [sg.T("", size=(20, 1)), sg.Button("Encrypt", pad=(5, 10), key="encrypt"), sg.T("vvv   ^^^"), sg.Button("Decrypt", pad=(5, 10), key="decrypt")],

            [sg.T("Private Key", size=(10, 1)), sg.TabGroup([[
                sg.Tab("From Text", [
                    [sg.In(key="privkey_text", size=(55, 1))]
                ], key="privkey_text_tab"),
                sg.Tab("From File", [
                    [sg.T("Select File", size=(10, 1)), sg.FileBrowse("Choose a file", key="privkey_file", target=(sg.ThisRow, 2)), sg.T("", size=(30, 2))],
                ], key="privkey_file_tab"),
            ]], key="privkey_source")],
            [sg.T("Ciphertext", size=(10, 1)), sg.In(key="ciphertext", size=(60, 1))],

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

            # Validate
            case ("validate" as event, {
                "method": "ECC",
                "ecc_a": a,
                "ecc_b": b,
                "ecc_p": p,
                "ecc_base": base,
            }):
                cipher = ECC(a=int(a), b=int(b), p=int(p), base=int(base))
                cipher.validate_input()
                n = len(cipher.curve.all_points)
                base_point = cipher.curve.encode(cipher.base)
                debug_text, debug_color = f"Succesfully validated! num_points:{n}, base:{base_point}", Config.SUCCESS_COLOR

            # Encrypt / Decrypt
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
                        cipher_args = {
                            "plaintext": int(plaintext),
                            "pubkey": pubkey if pubkey_source == "pubkey_text_tab" else load_file(pubkey_file)[0],
                        }
                        if method == "ECC":
                            cipher_args |= {
                                "pubkey": int(cipher_args["pubkey"]),
                                "a": int(values["ecc_a"]),
                                "b": int(values["ecc_b"]),
                                "p": int(values["ecc_p"]),
                                "base": int(values["ecc_base"]),
                            }
                        cipher = cipher(**cipher_args)
                        cipher.encrypt()
                        window["ciphertext"].update(str(cipher.ciphertext))

                    case ("decrypt", {
                        "ciphertext": ciphertext,
                        "privkey_text": privkey,
                        "privkey_file": privkey_file,
                        "privkey_source": privkey_source,
                    }):
                        # Read privkey
                        privkey = privkey if privkey_source == "privkey_text_tab" else load_file(privkey_file)[0]
                        if method not in ["Paillier"]:
                            privkey = int(privkey)
                        ciphertext = int(ciphertext)
                        cipher = cipher(ciphertext=ciphertext, privkey=privkey)
                        cipher.decrypt()
                        window["plaintext"].update(str(cipher.plaintext))

                debug_text, debug_color = f"Succesfully {event}ed!", Config.SUCCESS_COLOR

            # Generate Key
            case ("generate", {
                "keygen_method": "RSA_",
                # TODO chel
                # "keygen_rsa_x": x,
            }):
                privkey_gen, pubkey_gen = RSA().generate_key()  # TODO chel
                window["pubkey_gen"].update(str(pubkey_gen))
                window["privkey_gen"].update(str(privkey_gen))
                debug_text, debug_color = "Successfully generated key!", Config.SUCCESS_COLOR
            case ("generate", {
                "keygen_method": "ElGamal_",
                # TODO chel
                # "keygen_elgamal_x": x,
            }):
                privkey_gen, pubkey_gen = ElGamal().generate_key()  # TODO chel
                window["pubkey_gen"].update(str(pubkey_gen))
                window["privkey_gen"].update(str(privkey_gen))
                debug_text, debug_color = "Successfully generated key!", Config.SUCCESS_COLOR
            case ("generate", {
                "keygen_method": "ECC_",
                "keygen_ecc_a": a,
                "keygen_ecc_b": b,
                "keygen_ecc_p": p,
            }):
                privkey_gen, pubkey_gen = ECC(int(a), int(b), int(p)).generate_key()
                window["pubkey_gen"].update(str(pubkey_gen))
                window["privkey_gen"].update(str(privkey_gen))
                debug_text, debug_color = "Successfully generated key!", Config.SUCCESS_COLOR
            case ("generate", {
                "keygen_method": "Paillier_",
                "keygen_paillier_p": p,
                "keygen_paillier_q": q,
                "keygen_paillier_g": g,
            }):
                privkey_gen, pubkey_gen = Paillier().generate_key(int(p), int(q), int(g))
                window["pubkey_gen"].update(str(pubkey_gen))
                window["privkey_gen"].update(str(privkey_gen))
                debug_text, debug_color = "Successfully generated key!", Config.SUCCESS_COLOR

            # Save To File
            case (event, {
                "keygen_filename": keygen_filename,
                "filename": filename,
            }) if (
                (event == "save_keygen" and keygen_filename == "") or
                (event in ["save_plaintext", "save_ciphertext"] and filename == "")
            ):
                debug_text, debug_color = "Output filename cannot be empty", Config.FAIL_COLOR
            case ("save_keygen", {
                "keygen_filename": keygen_filename,
                "pubkey_gen": pubkey,
                "privkey_gen": privkey,
            }):
                write_file("out/" + keygen_filename + ".pub", pubkey)
                write_file("out/" + keygen_filename + ".pri", privkey)
                debug_text, debug_color = f"Successfully saved public / private key pair as {keygen_filename}.pub and {keygen_filename}.pri!", Config.SUCCESS_COLOR
            case ("save_plaintext", {"filename": filename}):
                filename = "out/" + filename
                write_file(filename, cipher.plaintext)
                debug_text, debug_color = f"Successfully saved plaintext as {filename}!", Config.SUCCESS_COLOR
            case ("save_ciphertext", {"filename": filename}):
                filename = "out/" + filename
                write_file(filename, cipher.ciphertext)
                debug_text, debug_color = f"Successfully saved ciphertext as {filename}!", Config.SUCCESS_COLOR

    except Exception as e:
        debug_text, debug_color = str(e), Config.FAIL_COLOR

    window["debug"].update(debug_text)
    window["debug"].update(background_color=debug_color)

window.close()
