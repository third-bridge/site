;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.alpha.v3.authorization
  (:require
   [xtdb.api :as xt]
   [clojure.tools.logging :as log]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(defn check-permissions
  "Given a subject, possible actions and resource, return all related pairs of permissions and actions."
  [db {:keys [subject actions purpose resource rules]}]
  (xt/q
   db
   {:find '[(pull permission [*]) (pull action [*])]
    :keys '[permission action]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [permission ::pass/purpose purpose]
      [(contains? actions action)]
      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions purpose resource]}

   subject actions purpose resource))

(defn allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed?"
  [db {:keys [subject actions purpose rules]}]
  (xt/q
   db
   {:find '[resource]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [permission ::pass/purpose purpose]
      [(contains? actions action)]

      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions purpose]}

   subject actions purpose))

(defn allowed-subjects
  "Given a resource and a set of actions, which subjects can access and via which
  actions?"
  [db {:keys [resource actions purpose rules]}]
  (->> (xt/q
        db
        {:find '[subject action]
         :keys '[subject action]
         :where
         '[
           [permission ::site/type "Permission"]
           [action ::site/type "Action"]
           [permission ::pass/action action]
           [permission ::pass/purpose purpose]
           [(contains? actions action)]

           (allowed? permission subject action resource)]

         :rules rules

         :in '[resource actions purpose]}

        resource actions purpose)))

(defn pull-allowed-resource
  "Given a subject, a set of possible actions and a resource, pull the allowed
  attributes."
  [db {:keys [subject actions purpose resource rules]}]
  (let [check-result (check-permissions
                      db
                      {:subject subject
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
  [db {:keys [subject actions purpose rules include-rules]}]
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
                    [permission ::pass/purpose purpose]
                    [(contains? actions action)]

                    (allowed? permission subject action resource)]
            include-rules
            (conj '(include? subject action resource)))

          :rules (vec (concat rules include-rules))

          :in '[subject actions purpose]}

         subject actions purpose)
        pull-expr (vec (mapcat (comp ::pass/pull :action) results))]

    (->> results
         (map :resource)
         (xt/pull-many db pull-expr))))


(defn call-action [db subject action resource rules action-args]
  (try
    ;; Check that we /can/ call the action
    (let [check-permissions-result (check-permissions db {:subject subject
                                                          :actions #{action}
                                                          :rules rules})]
      (when (seq check-permissions-result)
        (mapv (fn [{:keys [permission action]}]
                [::xt/put {:xt/id :foo}])
              check-permissions-result)))

    (catch Exception e
      (log/errorf e "Error when calling action: %s" action)
      (throw e))))

(defn submit-call-action-sync [xt-node {:keys [subject action resource rules args]}]
  (let [tx (xt/submit-tx
            xt-node
               [[::xt/fn ::pass/call-action subject action resource rules args]])]

       (xt/await-tx xt-node tx)
       (assert (xt/tx-committed? xt-node tx))))

(defn register-call-action-fn []
  [::xt/put
   {:xt/id ::pass/call-action
    :xt/fn '(fn [xt-ctx subject action resource rules action-args]
              (juxt.pass.alpha.v3.authorization/call-action (xtdb.api/db xt-ctx) subject action resource rules action-args))}])
