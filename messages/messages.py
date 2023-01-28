from colorama import Fore


class Certificate:
    success = '\t✅ ' + Fore.LIGHTGREEN_EX + "Succès! " + Fore.RESET
    error = ' ❌' + Fore.LIGHTRED_EX + "Erreur! " + Fore.RESET
    warning = ' ⚠️' + Fore.LIGHTYELLOW_EX + "Attention! " + Fore.RESET
    info = ' ℹ️' + Fore.LIGHTBLUE_EX + "Info! " + Fore.RESET
