import xml.etree.ElementTree as ET

from OSMPythonTools.overpass import Overpass

api = Overpass()

with open('trees.txt', 'r') as f:
    trees = f.readlines()
    trees = [line.strip() for line in trees]

root = ET.Element('osm', version='0.6', generator='unitedCTF2025PythonScript')
for i, tree in enumerate(trees):
    print(f'Processing tree {i + 1}/{len(trees)}: {tree}')
    result = api.query(f'node({tree}); out body;')
    node = ET.SubElement(root, 'node', id=str(result.elements()[0].id()), lat=str(result.elements()[0].lat()), lon=str(result.elements()[0].lon()), version="1")

    xml_tree = ET.ElementTree(root)
    xml_tree.write('solve.osm', encoding='utf-8', xml_declaration=True)
print('OSM file created, open it in JOSM: solve.osm')
