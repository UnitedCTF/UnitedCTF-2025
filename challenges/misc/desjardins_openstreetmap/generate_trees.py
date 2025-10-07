import xml.etree.ElementTree as ET

from OSMPythonTools.element import Element
from OSMPythonTools.overpass import Overpass
from PIL import Image

image = Image.open('flag.png')
pixels = image.getdata()
width, height = image.size
matrix = []
number_of_points = 0
row_number = 0
for i, pixel in enumerate(pixels):
    if i % width == 0:
        matrix.append([0] * width)

    if pixel[0] == 255:
        matrix[row_number][i % width] = 0
    else:
        matrix[row_number][i % width] = 1
        number_of_points += 1
    row_number += 1 if (i + 1) % width == 0 else 0

min_lat = 45.5422
min_lon = -73.6314

max_lat = 45.4883
max_lon = -73.5476
# min_lat = 48.88222
# min_lon = 2.28790
#
# max_lat = 48.83083
# max_lon = 2.39450

lat_width = max_lat - min_lat
lon_width = max_lon - min_lon

api = Overpass()

root = ET.Element('osm', version='0.6', generator='unitedCTF2025PythonScript')
tree = ET.ElementTree(root)


def find_closest_node(lat: float, lon: float, nodes: list[Element]) -> Element:
    """
    Find the closest node to the specified latitude and longitude.
    """
    closest_node = None
    min_distance = float('inf')
    for node in nodes:
        distance = ((node.lat() - lat) ** 2 + (node.lon() - lon) ** 2) ** 0.5
        if distance < min_distance:
            min_distance = distance
            closest_node = node
    return closest_node

i = 0
with open('trees.txt', 'w') as f:
    for row in range(len(matrix)):
        for col in range(len(matrix[row])):
            if matrix[row][col] == 1:
                i += 1
                print(f'{i} / {number_of_points} ({round((i / number_of_points) * 100, 2)} %)')
                lat = min_lat + (row / len(matrix)) * lat_width
                lon = min_lon + (col / len(matrix[row])) * lon_width
                print(f'Querying for trees near ({col}, {row}) ({lat}, {lon})')
                results = api.query(f'node(around:40, {round(lat, 5)}, {round(lon, 5)})["natural"="tree"];out meta;')
                if results.nodes():
                    result = find_closest_node(lat, lon, results.nodes())
                    node_xml = ET.SubElement(root, 'node', id=str(result.id()), lat=str(result.lat()), lon=str(result.lon()), version='1')
                    tree.write('flag.osm', encoding='utf-8', xml_declaration=True)
                    f.writelines([str(result.id()) + '\n'])
