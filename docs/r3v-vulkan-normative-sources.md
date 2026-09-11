# R3V Vulkan normative source references

The API registry inventories commands and types. The prose specification defines
the memory and synchronization obligations that cross the R3V and DRM boundary.
`policy/r3v-vulkan-drm-requirements.json` retains selected exact excerpts from
Khronos Vulkan-Docs commit `ab08f0951ef1ad9b84db93f971e113c1d9d55609`.
The registry pins Mesa and kernel source baselines separately from later repairs.

## Offline reproduction

The caller supplies an existing Vulkan-Docs checkout or bare Git cache containing
the pinned commit. Its upstream is
<https://github.com/KhronosGroup/Vulkan-Docs>.
Source acquisition occurs separately from validation. The checker reads Git
objects and emits its verdict to standard output.

```sh
"$PYTHON" -W error scripts/check_r3v_drm_requirement_sources.py \
  --mesa-tree "$MESA_TREE" --vulkan-tree "$VULKAN_TREE" --selftest
"$PYTHON" -O -W error scripts/check_r3v_drm_requirement_sources.py \
  --mesa-tree "$MESA_TREE" --vulkan-tree "$VULKAN_TREE" --selftest
ruff check scripts/check_r3v_drm_requirement_sources.py
```

`$PYTHON` names the caller-selected interpreter. `CHAPTER_BLOBS` pins the Git
blob identity of each chapter under `doc/specs/vulkan/chapters/`. The checker
accepts standalone and bullet-form anchor declarations. An excerpt matches
literal source text after its anchor and before the next declaration. A
cross-reference to an anchor supplies neither a declaration nor an excerpt.

## Evidence boundary

The six excerpts cover the coherent memory-type minimum, buffer binding size,
memory dependency ordering, visibility, queue fence scope, and finite waits
after device loss. The lost-device excerpt preserves the swapchain conditional
directives so extension scope remains explicit.

The excerpt check establishes source identity and location. Human review still
determines whether a quotation supports each interpretation. Additional clauses
for coherent cache semantics, binding alignment and memory types, access scopes,
and lost-device object lifetime remain to be quoted. Allocation, image binding,
packet admission, and suspend require additional mappings. The tracker keeps
behavioral tests at `not_run`; parser execution and retained target observations
remain separate evidence in `steinmarder-r300`.

A signaled fence and a visible payload answer different questions. Fence scope
orders operations; availability and visibility govern the values that consumers
can access. Qualification tests record ordering and directional payload checks
separately.
