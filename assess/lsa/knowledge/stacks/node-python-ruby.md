# Stack Notes — Older Node.js (Express 3/4), Python (Django ≤1.x, Flask, web.py), Ruby (Rails 2–4, Sinatra)

## Node.js / Express

- Routes: `app.get|post|put|delete|all('/path/:id', mw1, mw2, handler)`,
  `router.*` mounted with `app.use('/prefix', router)`. Middleware order
  matters: `app.use(auth)` only protects routes declared **after** it.
- Auth: `passport.authenticate`, `ensureLoggedIn`, `req.session.user`,
  `req.user` (set by verified middleware = trustworthy).
- Ownership: `Order.findOne({_id: req.params.id, owner: req.user._id})` safe;
  `Order.findById(req.params.id)` unsafe without comparison.
- Inputs: `req.params`, `req.query`, `req.body`, `req.cookies`,
  `req.headers`. With `qs`/`body-parser extended:true`, query values can be
  **objects** → NoSQL operator injection.
- Sinks: `connection.query("..." + x)`, template literals, `sequelize.query`,
  `knex.raw`, Mongo `$where`, `find(req.query)`.

## Python

- Django: `urls.py` `url(r'^order/(?P<id>\d+)/$', views.detail)` /
  `path('order/<int:id>/', ...)`; auth `@login_required` (login only!),
  `LoginRequiredMixin`; ownership `get_object_or_404(Order, id=id, user=request.user)`
  safe vs `Order.objects.get(id=id)` unsafe.
  Sinks: `cursor.execute("..." % x)`, `.raw("..." + x)`, `.extra(where=[...])`.
- Flask: `@app.route('/order/<int:id>', methods=[...])`, `@login_required`
  (Flask-Login), `current_user`; sinks `db.engine.execute("..." + x)`,
  `cursor.execute(f"...{x}")`. Safe: `cursor.execute("... %s", (x,))`
  (**comma = param binding**; `%` = string formatting — easy to confuse).
- web.py: `urls = ('/order/(\d+)', 'Order')` class with `GET/POST`;
  `db.query("..." + x)` unsafe; `db.query("... $id", vars={'id': x})` safe.

## Ruby

- Rails: `config/routes.rb` `resources :orders`, `match ':controller(/:action(/:id))'`
  (Rails 2/3 catch-all → every public controller method is reachable!).
  Auth `before_filter :authenticate_user!` / `before_action`; `skip_before_filter`
  exceptions. Ownership: `current_user.orders.find(params[:id])` safe;
  `Order.find(params[:id])` unsafe.
  Sinks: `where("id = #{params[:id]}")`, `find_by_sql`, `order(params[:sort])`,
  `find(:all, :conditions => "... #{x}")` (Rails 2), `connection.execute`.
  Safe: `where(id: x)`, `where("id = ?", x)`.
- Sinatra: `get '/order/:id' do ... end`; `before do ... end` filters.
