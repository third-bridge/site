;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.alpha.v3.authorization
  (:require
   [xtdb.api :as xt]
   [clojure.tools.logging :as log]
   [malli.core :as m]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'pass.malli (create-ns 'juxt.pass.alpha.malli))
(alias 'site (create-ns 'juxt.site.alpha))

(defn actions->rules
  "Determine rules for the given action ids. Each rule is bound to the given
  action."
  [db actions]
  (vec (for [action actions
             :let [e (xt/entity db action)]
             rule (::pass/rules e)]
         (conj rule ['action :xt/id action]))))

(defn check-permissions
  "Given a subject, possible actions and resource, return all related pairs of permissions and actions."
  [db {:keys [access-token scope actions purpose resource rules]}]

  (assert (seq rules) "No rules provided")

  (xt/q
   db
   {:find '[(pull permission [*]) (pull action [*])]
    :keys '[permission action]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]

      ;; Purpose
      [permission ::pass/purpose purpose]

      ;; Scope
      [action ::pass/scope action-scope]
      [(contains? scope action-scope)]

      [(contains? actions action)]
      (allowed? permission access-token action resource)]

    :rules rules

    :in '[access-token scope actions purpose resource]}

   access-token scope actions purpose resource))

(defn allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed?"
  [db {:keys [access-token scope actions purpose rules]}]
  (xt/q
   db
   {:find '[resource]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]

      ;; Purpose
      [permission ::pass/purpose purpose]

      ;; Scope
      [action ::pass/scope action-scope]
      [(contains? scope action-scope)]

      [(contains? actions action)]
      (allowed? permission access-token action resource)]

    :rules rules

    :in '[access-token scope actions purpose]}

   access-token scope actions purpose))

;; TODO: How is this call protected from unauthorized use? Must call this with
;; access-token to verify subject.
(defn allowed-subjects
  "Given a resource and a set of actions, which subjects can access and via which
  actions?"
  [db {:keys [resource actions purpose scope rules]}]
  (->> (xt/q
        db
        {:find '[subject action]
         :keys '[subject action]
         :where
         '[
           [permission ::site/type "Permission"]
           [action ::site/type "Action"]
           [permission ::pass/action action]

           ;; Purpose
           [permission ::pass/purpose purpose]

           ;; Scope
           [action ::pass/scope action-scope]
           [(contains? scope action-scope)]

           [(contains? actions action)]
           [access-token ::pass/subject subject]

           (allowed? permission access-token action resource)]

         :rules rules

         :in '[resource actions purpose scope]}

        resource actions purpose scope)))

(defn pull-allowed-resource
  "Given a subject, a set of possible actions and a resource, pull the allowed
  attributes."
  [db {:keys [access-token scope actions purpose resource rules]}]
  (let [check-result (check-permissions
                      db
                      {:access-token access-token
                       :scope scope
                       :actions actions
                       :purpose purpose
                       :resource resource
                       :rules rules})
        pull-expr (vec (mapcat
                        (fn [{:keys [action]}]
                          (::pass/pull action))
                        check-result))]
    (xt/pull db pull-expr resource)))

(defn pull-allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed, and
  get me the documents"
  [db {:keys [access-token scope actions purpose rules include-rules]}]
  (let [results
        (xt/q
         db
         {:find '[resource (pull action [::xt/id ::pass/pull]) purpose permission]
          :keys '[resource action purpose permission]
          :where
          (cond-> '[
                    [permission ::site/type "Permission"]
                    [action ::site/type "Action"]
                    [permission ::pass/action action]

                    ;; Purpose
                    [permission ::pass/purpose purpose]

                    ;; Scope
                    [action ::pass/scope action-scope]
                    [(contains? scope action-scope)]

                    [(contains? actions action)]

                    (allowed? permission access-token action resource)]
            include-rules
            (conj '(include? access-token action resource)))

          :rules (vec (concat rules include-rules))

          :in '[access-token scope actions purpose]}

         access-token scope actions purpose)
        pull-expr (vec (mapcat (comp ::pass/pull :action) results))]

    (->> results
         (map :resource)
         (xt/pull-many db pull-expr))))

(defmulti apply-processor (fn [processor m arg-def] (first processor)))

(defmethod apply-processor :default [[kw] m _]
  (log/warnf "No processor for %s" kw)
  m)

(defmethod apply-processor ::pass/merge [[_ m-to-merge] val _]
  (merge val m-to-merge))

(defmethod apply-processor ::pass.malli/validate [[_ form] val {::pass.malli/keys [schema]}]
  (assert schema)
  (when-not (m/validate schema val)
    (throw
     (ex-info
      "Failed validation check"
      (m/explain schema val))))
  val)

(defn process-arg [arg arg-def]
  (reduce
   (fn [acc processor]
     (apply-processor processor acc arg-def))
   arg
   (::pass/process arg-def)))

(defn call-action [db access-token scope action resource rules action-args]
  (try
    ;; Check that we /can/ call the action
    (let [check-permissions-result
          (check-permissions
           db
           {:access-token access-token
            :scope scope
            :actions #{action}
            :rules rules
            :resource resource})
          action-doc (xt/entity db action)
          _ (when-not action-doc (throw (ex-info "Action not found in db" {:action action})))
          action-arg-defs (::pass/action-args action-doc [])
          _ (when-not (= (count action-arg-defs) (count action-args))
              (throw
               (ex-info
                "Arguments given to call-action do not match the number of arguments defined on the action"
                {:count-action-arg-defs (count action-arg-defs)
                 :count-action-args (count action-args)})))]

      (when-not (seq check-permissions-result)
        (throw (ex-info "Don't have permission!" {})))

      (mapv
       (fn [arg arg-def]
         [::xt/put (process-arg arg arg-def)])

       action-args action-arg-defs))

    (catch Exception e
      (log/errorf e "Error when calling action: %s" action)
      (throw e))))

(defn call-action! [xt-node {:keys [access-token scope action resource rules args]}]
  (let [tx (xt/submit-tx
            xt-node
            [[::xt/fn "urn:site:tx-fns:call-action" access-token scope action resource rules args]])]

    (xt/await-tx xt-node tx)
    (assert (xt/tx-committed? xt-node tx))))

(defn register-call-action-fn []
  {:xt/id "urn:site:tx-fns:call-action"
   :xt/fn '(fn [xt-ctx access-token scope action resource rules action-args]
             (juxt.pass.alpha.v3.authorization/call-action (xtdb.api/db xt-ctx) access-token scope action resource rules action-args))})
