import os
import random

def create_directory(name, depth, is_flag_placed, max_width=5):
    if depth == 0:
        return is_flag_placed

    # Directions de la rose des vents (compass rose directions)
    compass_directions = [
        'N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE',
        'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'
    ]

    dirs_to_create = random.randint(1, min(max_width, len(compass_directions)))
    flag_dir = random.randint(0, dirs_to_create-1) if depth == 1 and not is_flag_placed else -1
    
    # Mélanger les directions pour avoir un ordre aléatoire
    available_directions = compass_directions.copy()
    random.shuffle(available_directions)

    for i in range(dirs_to_create):
        dir_name = available_directions[i]
        new_path = os.path.join(name, dir_name)
        os.makedirs(new_path, exist_ok=True)

        if i == flag_dir:
            with open(os.path.join(new_path, 'flag.txt'), 'w') as f:
                f.write("flag-longleat_maze_discount_navigation_master")
            is_flag_placed = True
        else:
            is_flag_placed = create_directory(new_path, depth-1, is_flag_placed, max_width)

    return is_flag_placed

# Entry point of the script
def main():
    base_path = 'longleat_maze'
    depth = 9  # Profondeur du labyrinthe
    os.makedirs(base_path, exist_ok=True)
    create_directory(base_path, depth, False)

if __name__ == '__main__':
    main()
