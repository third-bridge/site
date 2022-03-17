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
  [db subject actions {:keys [resource purpose]}]

  (let [rules (actions->rules db actions)]
    (when (seq rules)
      (xt/q
       db
       {:find '[(pull permission [*]) (pull action [*])]
        :keys '[permission action]
        :where
        '[
          [action ::site/type "Action"]

          ;; Only consider given actions
          [(contains? actions action)]

          ;; Only consider a permitted action
          [permission ::site/type "Permission"]
          [permission ::pass/action action]
          (allowed? permission subject action resource)

          ;; Only permissions that match our purpose
          [permission ::pass/purpose purpose]]

        :rules rules

        :in '[subject actions resource purpose]}

       subject actions resource purpose))))

(defn allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed?"
  [db subject actions {:keys [purpose]}]
  (let [rules (actions->rules db actions)]
    (xt/q
     db
     {:find '[resource]
      :where
      '[
        [action ::site/type "Action"]

        ;; Only consider given actions
        [(contains? actions action)]

        ;; Only consider a permitted action
        [permission ::site/type "Permission"]
        [permission ::pass/action action]
        (allowed? permission subject action resource)

        ;; Only permissions that match our purpose
        [permission ::pass/purpose purpose]]

      :rules rules

      :in '[subject actions purpose]}

      subject actions purpose)))

;; TODO: How is this call protected from unauthorized use? Must call this with
;; access-token to verify subject.
(defn allowed-subjects
  "Given a resource and a set of actions, which subjects can access and via which
  actions?"
  [db resource actions {:keys [purpose]}]
  (let [rules (actions->rules db actions)]
    (->> (xt/q
          db
          {:find '[subject action]
           :keys '[subject action]
           :where
           '[
             [action ::site/type "Action"]

             ;; Only consider given actions
             [(contains? actions action)]

             ;; Only consider a permitted action
             [permission ::site/type "Permission"]
             [permission ::pass/action action]
             (allowed? permission subject action resource)

             ;; Only permissions that match our purpose
             [permission ::pass/purpose purpose]

             #_[access-token ::pass/subject subject]]

           :rules rules

           :in '[resource actions purpose]}

          resource actions purpose))))

(defn pull-allowed-resource
  "Given a subject, a set of possible actions and a resource, pull the allowed
  attributes."
  [db subject actions resource {:keys [purpose]}]
  (let [check-result
        (check-permissions
         db
         subject
         actions
         {:purpose purpose
          :resource resource})

        pull-expr (vec (mapcat
                        (fn [{:keys [action]}]
                          (::pass/pull action))
                        check-result))]
    (xt/pull db pull-expr resource)))

(defn pull-allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed, and
  get me the documents"
  [db subject actions {:keys [purpose include-rules]}]
  (let [rules (actions->rules db actions)
        results
        (xt/q
         db
         {:find '[resource (pull action [::xt/id ::pass/pull]) purpose permission]
          :keys '[resource action purpose permission]
          :where
          (cond-> '[
                    [action ::site/type "Action"]

                    ;; Only consider given actions
                    [(contains? actions action)]

                    ;; Only consider a permitted action
                    [permission ::site/type "Permission"]
                    [permission ::pass/action action]
                    (allowed? permission subject action resource)

                    ;; Only permissions that match our purpose
                    [permission ::pass/purpose purpose]]

            include-rules
            (conj '(include? subject action resource)))

          :rules (vec (concat rules include-rules))

          :in '[subject actions purpose]}

         subject actions purpose)

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

(defmethod apply-processor ::pass.malli/validate [_ val {::pass.malli/keys [schema]}]
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

(defn call-action [db {:keys [resource purpose]} subject action action-args]
  (try
    ;; Check that we /can/ call the action
    (let [check-permissions-result
          (check-permissions
           db
           subject
           #{action}
           {:resource resource :purpose purpose})
          action-doc (xt/entity db action)
          _ (when-not action-doc
              (throw
               (ex-info
                (format "Action '%s' not found in db" action)
                {:action action})))
          action-arg-defs (::pass/action-args action-doc [])
          _ (when-not (= (count action-arg-defs) (count action-args))
              (throw
               (ex-info
                "Arguments given to call-action do not match the number of arguments defined on the action"
                {:count-action-arg-defs (count action-arg-defs)
                 :count-action-args (count action-args)})))]

      (when-not (seq check-permissions-result)
        (throw
         (ex-info
          (str "Don't have permission! " (pr-str {:subject subject
                                                 :action action
                                                 :resource resource
                                                 :purpose purpose}))
          {:subject subject
           :action action
           :resource resource
           :purpose purpose})))

      (mapv
       (fn [arg arg-def]
         [::xt/put (process-arg arg arg-def)])

       action-args action-arg-defs))

    (catch Exception e
      (log/errorf e "Error when calling action: %s" action)
      (throw e))))

(defn call-action! [xt-node pass-ctx subject action & args]
  (let [tx (xt/submit-tx
            xt-node
            [[::xt/fn "urn:site:tx-fns:call-action" pass-ctx subject action args]])]

    (xt/await-tx xt-node tx)
    (assert (xt/tx-committed? xt-node tx))))

(defn register-call-action-fn []
  {:xt/id "urn:site:tx-fns:call-action"
   :xt/fn '(fn [xt-ctx pass-ctx subject action args]
             (juxt.pass.alpha.v3.authorization/call-action (xtdb.api/db xt-ctx) pass-ctx subject action args))})
