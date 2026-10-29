# Mass Assignment Patterns in Legacy Code

Mass assignment (OWASP API3:2023 Broken Object Property Level Authorization,
CWE-915): the request decides **which properties** of an object are written.
A caller adds `role=admin`, `owner_id=7`, `price=0` or `status=approved` to a
normal form or JSON body and the code stores it.

## 1. Tier 1 candidates

`find_mass_assignment.py` writes `OUT/mass-assignment.candidates.json`. Each
candidate is a hint for the auditor, not a finding.

| Field | Meaning |
|---|---|
| `subtype` | `whole_object_binding` (body / every form field bound to an object) or `privileged_field_writable` (a privileged field written from input, or listed in a model's allow-list) |
| `rule` | the shape that matched, e.g. `js-model-call`, `php-eloquent-static`, `java-entity-binding` |
| `target` | model or entity name when it can be read from the line |
| `allowlist` | `none` (known open: `$guarded = []`, JPA entity, EF entity), `seen` (allow-list exists but holds a privileged field), `unknown` |
| `sensitive_fields` | privileged names found (`role`, `is_admin`, `owner_id`, `tenant_id`, `price`, `balance`, `status`, …) |
| `priority` | `high` for known-open models, privileged fields, `extract($_POST)` and loops over all input |

Model facts are collected from the **whole tree** (also in diff mode): Laravel
`$fillable` / `$guarded`, JPA `@Entity` classes, Entity Framework `DbSet<T>`.
Bindings to DTO or form classes that are not entities are not reported.

## 2. Vulnerable patterns (report these)

| Stack | Shape |
|---|---|
| Node / Express | `Model.create(req.body)`, `Model.findByIdAndUpdate(id, req.body)`, `new Model(req.body)`, `Object.assign(entity, req.body)`, `{ ...req.body }`, `_.merge(entity, req.body)` |
| PHP | `extract($_POST)`, `foreach ($_POST as $k => $v) { $obj->$k = $v; }`, CodeIgniter `$this->db->update('t', $this->input->post())` |
| Laravel | `Model::create($request->all())` or `->fill($request->all())` when the model has `$guarded = []` or no allow-list; `$fillable` that includes a privileged field |
| Java Spring | `@ModelAttribute Entity e` / `@RequestBody Entity e` where `Entity` is a JPA `@Entity`; `BeanUtils.populate(entity, request.getParameterMap())`; `BeanUtils.copyProperties(form, entity)` |
| ASP.NET MVC | Action parameter of an EF entity type without `[Bind(Include = …)]`; `TryUpdateModel(entity)` / `UpdateModel(entity)` without a property list |
| Python | `Model(**request.json)`, `Model.objects.create(**request.POST.dict())`, `obj.__dict__.update(request.form)`, `for k, v in request.json.items(): setattr(obj, k, v)`, Django `ModelForm` with `fields = '__all__'` |
| Ruby on Rails | `params.permit!`, `Model.new(params[:model])` without strong parameters |
| Classic ASP | `For Each f In Request.Form` writing `rs(f) = Request.Form(f)` |
| ColdFusion | `StructAppend(obj, form)`, `<cfloop collection="#form#">` copying every field |
| Any | `user.role = $_POST['role']`, `user.isAdmin = req.body.isAdmin`, `order['price'] = $_GET['price']` on a route the caller should not use to change that field |

## 3. Safe patterns (do not report)

- Explicit fields: `{ name: req.body.name }`, `$request->only(['name'])`,
  `params.require(:user).permit(:name, :email)`, `[Bind(Include = "Id,Name")]`,
  `TryUpdateModel(entity, new[] { "Name" })`.
- A request DTO / form class with only the editable fields, copied field by
  field into the entity.
- A model allow-list (`$fillable`, `attr_accessible`, `ModelForm.fields = [...]`)
  that holds no privileged field **for this caller**.
- Privileged fields set from the server (`order.price = product.price`,
  `post.owner_id = currentUser.id`) after the binding, so input cannot win.

## 4. False-positive traps

- **Server overwrites after binding.** `Object.assign(post, req.body); post.ownerId = req.user.id;`
  is safe for `ownerId` but not for other privileged fields; check each.
- **Admin-only route.** Binding everything on an endpoint only admins can call
  is usually acceptable; confirm the role check (see `bfla-patterns.md`).
- **The model has no privileged field.** A `Comment` with `text` and
  `created_at` only is low impact; say so and lower the severity.
- **Validation layer.** Joi / class-validator with `whitelist: true`,
  `forbidNonWhitelisted`, JSON schema with `additionalProperties: false`, or a
  serializer with explicit `fields` strips unknown properties before binding.
- **Framework defaults.** Rails 4+ raises on raw `params[:model]` unless
  `permit` is used; Laravel models with non-empty `$guarded` block those fields.

## 5. Severity guide (mass assignment)

| Writable field | Severity |
|---|---|
| Role, admin flag, permissions, tenant or owner of the record | critical |
| Price, balance, credit, refund amount, approval or payment status | high–critical |
| Verified / approved flags, account level or plan | high |
| Other business fields the caller should not edit | medium |
| Only harmless fields reachable | low (or no finding) |

Adjust with `severity-and-cwe.md`.
