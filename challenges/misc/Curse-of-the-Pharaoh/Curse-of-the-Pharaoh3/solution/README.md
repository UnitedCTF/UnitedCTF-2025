# Curse of the Pharaoh 3

## Write-up

There were two solutions to this challenge:

### Use Cheat Engine to find the amount of money the player has

Since you know how much money you have, you just need to find where this information is stored in memory and change it to 10000.

1. Open Cheat Engine.
2. Select the game process.
3. Do a first scan with the scan type "Exact Value" and the value type "4 Bytes" (since it's stored as an int) with the value 5 (the initial amount of money the player has).
4. Bribe the guard with 1$.
5. Change the scan value to 4 and do "Next Scan."
6. Repeat until there's only one address that corresponds. This is where the money value is stored.
7. Change the value at this address to 10000.
8. Bribe the guard with 10000$.

### Use dnSpy to modify the code in order to change the "Value" of the "MoneyComponent" of the player's entity

To achieve this, add the following lines after the foreach in the "BribingUISystem":

1. Open dnSpy.
2. Load the `Assembly-CSharp.dll` of the build.
3. Go to the "BribingUISystem." It is modifiable because it isn't burst compiled. This could've been done in any other non–burst-compiled system.
4. Right click → Modify method.
5. Add these lines of code after the `foreach`:

```c#
EntityQuery query = new EntityQueryBuilder(Allocator.Temp).WithAllRW<MoneyComponent>().WithAll<PlayerTag>().Build(EntityManager);
RefRW<MoneyComponent> money = query.GetSingletonRW<MoneyComponent>();
money.ValueRW.Value = 10000;
```

7. Modify the logic that displays the dialog so that it's always displayed or you won't be able to bribe the guard.
6. Press "Compile" and remove every line that causes an error.
7. Save your changes.
8. Run the game and bribe the guard with 10000$.

## Flag

`flag-8r1b3M4S73r`
