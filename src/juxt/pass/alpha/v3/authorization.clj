;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.alpha.v3.authorization
  (:require
   [xtdb.api :as xt]
   [clojure.tools.logging :as log]
   [clojure.walk :refer [postwalk]]
   [malli.core :as m]
   [malli.error :a me]))

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

(defmulti apply-processor (fn [processor pass-ctx action args] (first processor)))

(defmethod apply-processor :default [[kw] pass-ctx action args]
  (throw (ex-info (format "No processor for %s" kw) {:kw kw :action action})))

(defmethod apply-processor :juxt.pass.alpha.process/update-in [[kw ks f-sym & update-in-args] pass-ctx action args]
  (assert (vector? args))
  (let [f (case f-sym 'merge merge nil)]
    (when-not f
      (throw (ex-info "Unsupported update-in function" {:f f-sym})))
    (apply update-in args ks f update-in-args)))

(defmethod apply-processor ::xt/put [[kw ks] pass-ctx action args]
  (mapv (fn [arg] [::xt/put arg]) args))

(defmethod apply-processor ::pass.malli/validate [_ pass-ctx {::pass.malli/keys [args-schema] :as action} args]
  (let [resolved-args-schema (postwalk
                              (fn [x]
                                (or
                                 (when (and (vector? x) (= (first x) ::pass/resolve))
                                   (pass-ctx (second x)))
                                 x))
                              args-schema)]

    (when-not (m/validate resolved-args-schema args)
      (throw
       (ex-info
        "Failed validation check"
        ;; Not sure why Malli throws this error here: No implementation of
        ;; method: :-form of protocol: #'malli.core/Schema found for class: clojure.lang.PersistentVector
        ;;
        ;; Workaround is to pr-str and read-string
        (read-string (pr-str (m/explain args-schema args)))))))

  args)

(defn process-args [pass-ctx action args]
  (reduce
   (fn [args processor]
     (apply-processor processor pass-ctx action args))
   args
   (::pass/process action)))

(defn do-action*
  [xt-ctx
   {resource ::site/resource
    purpose ::pass/purpose
    subject ::pass/subject
    action ::pass/action
    :as pass-ctx}
    args]
  (assert (vector? args))
  (let [db (xt/db xt-ctx)
        tx (xt/indexing-tx xt-ctx)]
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
                  {:action action})))]

        (when-not (seq check-permissions-result)
          (throw
           (ex-info
            "Action denied"
            {:subject subject
             :action action
             :resource resource
             :purpose purpose})))

        (let [processed-args (process-args pass-ctx action-doc args)]
          (conj
           processed-args
           [::xt/put
            (into
             {:xt/id (format "urn:site:action-log:%s" (::xt/tx-id tx))
              ::pass/subject subject
              ::pass/action action
              ::pass/purpose purpose
              ::pass/puts (vec
                           (keep
                            (fn [[tx-op {id :xt/id}]]
                              (when (= tx-op ::xt/put) id))
                            processed-args))
              ::pass/deletes (vec
                              (keep
                               (fn [[tx-op {id :xt/id}]]
                                 (when (= tx-op ::xt/delete) id))
                               processed-args))}
             tx)])))

      (catch Exception e
        (log/errorf e "Error when doing action: %s %s" action (format "urn:site:action-log:%s" (::xt/tx-id tx)))
        [[::xt/put
          {:xt/id (format "urn:site:action-log:%s" (::xt/tx-id tx))
           ::site/error {:message (.getMessage e)
                         :ex-data (ex-data e)}}]]))))

(defn install-do-action-fn []
  {:xt/id "urn:site:tx-fns:do-action"
   :xt/fn '(fn [xt-ctx pass-ctx args]
             (juxt.pass.alpha.v3.authorization/do-action* xt-ctx pass-ctx (vec args)))})

(defn do-action [xt-node pass-ctx subject action & args]
  (let [
        tx (xt/submit-tx
            xt-node
            [[::xt/fn "urn:site:tx-fns:do-action" (assoc pass-ctx ::pass/subject subject ::pass/action action) args]])
        {::xt/keys [tx-id]} (xt/await-tx xt-node tx)]

    ;; Throw a nicer error
    (when-not (xt/tx-committed? xt-node tx)
      (throw
       (ex-info
        "Transaction failed to be committed"
        {::xt/tx-id tx-id
         ::pass/action action})))

    (xt/entity
     (xt/db xt-node)
     (format "urn:site:action-log:%s" tx-id))))
