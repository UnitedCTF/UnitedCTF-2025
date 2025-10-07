from requests import post
from argparse import ArgumentParser

argpars = ArgumentParser(description="Generate PDF from markdown")
argpars.add_argument("level", type=int, help="Level number")

args = argpars.parse_args()


def get_pdf(level:int,lang:str):
    url = "https://md-to-pdf.fly.dev"
    css = """

    table {
    border-collapse: collapse;
    }

    table, th, td {
    border: 1px solid black;
    }

    th, td {
    text-align: left;
    padding: 1em;
    """
    input_file = f"commands_level{level}.{lang}.md"
    output_file = f"../level{level}/commands.{lang}.pdf"
    markdown =  open(input_file, "rb").read().decode("utf-8")

    r = post(url, data={"markdown": markdown, "css": css})
    r.text
    f = open(output_file, 'xb')
    for chunk in r.iter_content(chunk_size=512 * 1024): 
        if chunk: # filter out keep-alive new chunks
            f.write(chunk)
    f.close()

level = args.level

get_pdf(level,"en")
get_pdf(level,"fr")