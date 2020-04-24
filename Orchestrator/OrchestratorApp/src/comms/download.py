from ..mongo import mongo
from django.http import FileResponse
import csv
import os


def get_workspace_csv(workspace_string, resources):

    #Standing at comms
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUT_DIR = ROOT_DIR + '/out'
    workspace_string = workspace_string.split('/')
    workspace_name = workspace_string[len(workspace_string)-1]
    file_name = '/' + workspace_name+'.csv'

    try:
        os.remove(OUT_DIR+file_name)
    except FileNotFoundError:
        pass

    # Now we have a list of dicts
    with open(OUT_DIR+file_name, 'w+', encoding='utf8', newline='') as output_file:
        fc = csv.DictWriter(output_file,
                            fieldnames=resources[0].keys(),
                            )
        fc.writeheader()
        fc.writerows(resources)

    return FileResponse(open(OUT_DIR+file_name, 'rb'))
