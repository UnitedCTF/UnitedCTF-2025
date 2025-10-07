# Curse of the Pharaoh 4

## Write-up

The intended solution for this challenge is a DLL injection to enable an entity in the subscene. Because the "HealthSystem" is burst compiled, it is very hard to modify it with dnSpy. Instead the idea is to inject another system into the game that will enable the disabled entity that contains the flag and run in the right update group.

It is probably possible to add this code in the game without a DLL injection by just adding it in a regular class (with dnSpy), the code would probably be very similar.

Maybe it also could've been possible to deactivate the CharacterMovementSystem and then modify the players position so it can see the flag...

But here is the way I did it:

Here is the dll code to inject the proper system :

``` C#
using System.Threading;
using Unity.Collections;
using Unity.Entities;
using UnityEngine;


namespace DefaultNamespace
{
    public class Entry
    {
        static GameObject gameObject;
        public static void Init()
        {
            // Adds a game object with the "Injector" component to the game
            gameObject = new GameObject("InjectedGO");
            gameObject.AddComponent<Injector>();
        }

        public static void Unload()
        {
            UnityEngine.Object.Destroy(gameObject);
        }
    }

    public class Injector : MonoBehaviour
    {
        private bool initialized = false;

        public void Update()
        {
            if (!initialized && World.DefaultGameObjectInjectionWorld != null)
            {
                initialized = true;

                // Creates adds "MyInjectedSystem" to the update list so that it runs
                var sys = World.DefaultGameObjectInjectionWorld.GetOrCreateSystemManaged<MyInjectedSystem>();
                var simGroup = World.DefaultGameObjectInjectionWorld.GetExistingSystemManaged<LateSimulationSystemGroup>();
                simGroup.AddSystemToUpdateList(sys);
                simGroup.SortSystems();
            }
        }
    }

    [UpdateInGroup(typeof(LateSimulationSystemGroup))]
     // or
    [UpdateAfter(typeof(HealthSytem))]
    public partial class MyInjectedSystem : SystemBase
    { 
        EntityQuery _bossQuery;

        protected override void OnCreate()
        {
            EntityQueryBuilder builder = new EntityQueryBuilder(Allocator.Temp);
            _bossQuery = builder.WithAll<BossTag>().WithAllRW<BossDefeatedComponent>().WithOptions(EntityQueryOptions.IgnoreComponentEnabledState).Build(this);
        }

        protected override void OnUpdate()
        {
            EntityCommandBuffer ecb = new EntityCommandBuffer(Allocator.Temp);

            // Enables the flag container
            RefRW<BossDefeatedComponent> bossDefeated = _bossQuery.GetSingletonRW<BossDefeatedComponent>();
            ecb.SetEnabled(bossDefeated.ValueRW.FlagContainer, true);

            ecb.Playback(EntityManager);
        }
    }

}

```

Compile it as a DLL and then use a mono DLL injector like [this one](https://github.com/Ben00n/Unity-Injectors) and directly inject the DLL into the game.

The flag should appear next to the pharaoh.

## Flag

`flag-7r0yc43d`
